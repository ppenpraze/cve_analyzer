# Ansible CVE Inventory Collector — LLM Generation Prompt

> **Usage:** Paste this prompt (or the block below) into Claude, GPT-4, or another capable LLM
> to generate the Ansible playbook.  Attach `inventory_schema.json` as context if the model
> supports file uploads.

---

## Prompt

You are an expert Ansible engineer and Linux systems programmer.
Write a production-quality Ansible playbook called `inventory_collector.yml` that discovers
every significant software component on a fleet of RHEL 8/9 hosts and writes a structured
JSON inventory file consumed by a CVE analysis tool.

### Environment constraints

- Target OS: Red Hat Enterprise Linux 8 and 9 only (no Windows, no Debian derivatives).
- Hosts may be VMs, bare-metal servers, or container hosts running Podman or Docker.
- The environment is **loosely managed**: software is routinely deployed outside of RPM
  (JARs dropped into `/opt`, Python virtualenvs, compiled-from-source binaries, etc.).
  The collector must make a best-effort to find all of it.
- Assume SSH access with `become: true` (sudo).  Do not assume any agent is pre-installed.
- The playbook must complete in under **10 minutes** per host.  Skip subtasks that exceed
  a per-task timeout rather than failing the whole play.

---

### What to collect

Collect the following component types.  For each type, the table shows:
the Ansible/shell mechanism, the JSON `type` value, and the `detection_confidence` to assign.

| Component type | Discovery mechanism | JSON `type` | `detection_confidence` |
|---|---|---|---|
| RPM packages | `rpm -qa --queryformat` | `rpm` | `high` |
| Python packages (system) | `pip3 list --format=json` for each Python in `$PATH` | `python` | `medium` |
| Python packages (virtualenvs) | `find /opt /home /srv /var/www -name pyvenv.cfg -maxdepth 6`, then `pip list` inside each | `python` | `medium` |
| JAR files | `find` across non-excluded paths, then extract MANIFEST.MF and pom.properties | `jar` | `medium` |
| Node.js packages | `find` for `package.json` files (not nested node_modules), extract `name`+`version` | `node` | `medium` |
| Go binaries | `find` ELF executables, run `go version -m` on each | `go_module` | `medium` |
| Generic ELF binaries | In `/usr/local/bin`, `/opt`, `/srv` — try `--version`/`-v`/`version` flags | `binary` | `low` |

**Filesystem paths to always exclude from all `find` operations:**
`/proc /sys /dev /run /tmp /var/tmp /boot /snap`

**Additional JAR exclusions** (too noisy, not application code):
`/usr/share/java/openjdk* /usr/lib/jvm`

---

### Output schema

Write one JSON file per host to the Ansible controller at:
`./inventory/{{ inventory_hostname }}.json`

Then merge all per-host files into a single `inventory.json` at playbook completion.

The JSON must conform to this structure (see `inventory_schema.json` for the full JSON Schema):

```json
{
  "schema_version": "1.0",
  "generated_at": "<ISO-8601 UTC timestamp>",
  "collector": {
    "tool": "ansible-cve-inventory",
    "version": "1.0.0",
    "playbook": "inventory_collector.yml",
    "ansible_version": "{{ ansible_version.full }}"
  },
  "hosts": [
    {
      "hostname": "short-hostname",
      "fqdn": "fqdn.example.com",
      "ip_addresses": ["10.0.0.1"],
      "platform": {
        "type": "RHEL",
        "version": "9.2",
        "major": 9,
        "kernel": "5.14.0-284.30.1.el9_2.x86_64",
        "arch": "x86_64"
      },
      "components": [
        {
          "name": "curl",
          "version": "7.76.1",
          "type": "rpm",
          "path": null,
          "detection_confidence": "high",
          "rpm_fields": {
            "nevra": "curl-7.76.1-26.el9_2.2.x86_64",
            "release": "26.el9_2.2",
            "epoch": "0",
            "arch": "x86_64"
          }
        },
        {
          "name": "log4j-core",
          "version": "2.14.1",
          "type": "jar",
          "path": "/opt/myapp/lib/log4j-core-2.14.1.jar",
          "detection_confidence": "medium",
          "jar_fields": {
            "group_id": "org.apache.logging.log4j",
            "artifact_id": "log4j-core"
          }
        },
        {
          "name": "my-service",
          "version": "3.1.2",
          "type": "binary",
          "path": "/opt/myapp/bin/my-service",
          "detection_confidence": "low",
          "binary_fields": {
            "linked_libs": ["libssl.so.1.1", "libcrypto.so.1.1"],
            "version_string": "my-service version 3.1.2"
          }
        }
      ],
      "scan_metadata": {
        "scan_duration_s": 47.3,
        "rpm_count": 312,
        "jar_count": 8,
        "python_pkg_count": 15,
        "node_pkg_count": 0,
        "binary_count": 3,
        "scan_errors": ["Could not extract version from /opt/app/bin/worker"]
      }
    }
  ]
}
```

---

### Detailed collection requirements

#### 1. System metadata
```
ansible_facts: hostname, fqdn, all_ipv4_addresses, distribution_version,
               distribution_major_version, kernel, architecture
```
Parse `platform.type` from `ansible_facts.distribution` — "RedHat" maps to "RHEL".

#### 2. RPM packages
```bash
rpm -qa --queryformat '%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{EPOCH}\n'
```
- Set `epoch` to `"0"` when the RPM EPOCH field is `(none)`.
- Construct `nevra` as `{NAME}-{VERSION}-{RELEASE}.{ARCH}`.
- Set `path` to `null` for all RPMs.

#### 3. Python packages
- Discover all Python interpreters:
  ```bash
  find /usr /usr/local -name 'python3*' -type f -executable 2>/dev/null | sort -u
  ```
- For each interpreter run: `<interpreter> -m pip list --format=json 2>/dev/null`
- For each virtualenv found via `pyvenv.cfg`: `<venv>/bin/pip list --format=json`
- De-duplicate by `(name, version, path)` — same package in multiple venvs should appear once per unique path.
- Set `path` to the `site-packages` directory containing the package.

#### 4. JAR files
```bash
find / -xdev -name "*.jar" \
  -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" \
  -not -path "/usr/share/java/openjdk*" -not -path "/usr/lib/jvm/*" \
  2>/dev/null
```
For each JAR, attempt to extract (in order of preference):

1. **pom.properties** (Maven):
   ```bash
   unzip -p <jar> 'META-INF/maven/*/pom.properties' 2>/dev/null | head -20
   ```
   Extract `groupId`, `artifactId`, `version`.  Use `artifactId` as `name`.

2. **MANIFEST.MF** (fallback):
   ```bash
   unzip -p <jar> META-INF/MANIFEST.MF 2>/dev/null
   ```
   Extract `Implementation-Title` → `name`, `Implementation-Version` → `version`,
   `Bundle-SymbolicName` → `name` (if Implementation-Title absent).

3. If neither yields a version, set `version: null` and `detection_confidence: "low"`.

Limit JAR scanning to a **2-minute timeout** per host using `async`/`poll`.

#### 5. Node.js packages
```bash
find / -xdev -name "package.json" \
  -not -path "*/node_modules/*/node_modules/*" \
  -not -path "/proc/*" -not -path "/sys/*" \
  2>/dev/null
```
For each `package.json`, read `name` and `version` fields using `jq` or Python.
Skip files where `name` or `version` is absent.
Set `path` to the directory containing `package.json`.

#### 6. Go binaries
```bash
find /usr/local/bin /opt /srv -type f -executable 2>/dev/null
```
For each ELF binary, run:
```bash
go version -m <binary> 2>/dev/null
```
If it succeeds, the binary embeds Go module info.  Extract the module `path` and `mod` version.
If `go` is not installed, skip this step and log a scan_error.

#### 7. Generic ELF binaries
Scan `/usr/local/bin`, `/opt`, `/srv` for ELF executables not already captured by RPM or Go.
For each, attempt version extraction in this order:
```bash
timeout 5 <binary> --version 2>&1 | head -3
timeout 5 <binary> -v        2>&1 | head -3
timeout 5 <binary> version   2>&1 | head -3
```
Extract version using regex: `v?(\d+\.\d+[\.\d]*)`.  Take the first match.
Also run `ldd <binary> 2>/dev/null` and collect `linked_libs` (just the `.so` filenames,
not full paths — strip the path prefix and the `=>` resolved path).

---

### Error handling requirements

- **Never abort the whole play** due to a single component collection failure.
  Use `ignore_errors: true` and `failed_when: false` on discovery tasks.
- Capture all non-fatal errors in `scan_metadata.scan_errors` as plain strings.
- If a subtask times out, log `"<task> timed out after <N>s"` to `scan_errors` and continue.
- If `rpm` is not available (should not happen on RHEL but guard anyway), log and skip.
- If `unzip` is not available, attempt JAR metadata extraction with Python's `zipfile` module.

---

### Performance requirements

- Use `async` + `poll: 0` for JAR scanning and binary scanning (they are the slowest steps).
- Run host-level plays with `strategy: free` so fast hosts don't wait for slow ones.
- Use `gather_facts: true` (minimal) — do not disable fact gathering entirely.
- Target: **< 10 minutes per host** for a typical application server with ~500 RPMs and ~20 JARs.

---

### Ansible structure requirements

Produce the following files:

```
inventory_collector.yml      # Main playbook
roles/
  cve_inventory/
    tasks/
      main.yml               # Orchestrates all collection tasks
      rpm.yml                # RPM collection
      python.yml             # Python package collection
      jars.yml               # JAR scanning
      node.yml               # Node.js package collection
      go_binaries.yml        # Go binary scanning
      binaries.yml           # Generic ELF binary scanning
      assemble.yml           # Assemble and write JSON output
    defaults/
      main.yml               # Configurable defaults (scan paths, timeouts, etc.)
    templates/
      host_inventory.json.j2 # Jinja2 template for the per-host JSON output
```

**Configurable defaults** (in `defaults/main.yml`):
```yaml
cve_inventory_output_dir: "./inventory"
cve_inventory_jar_timeout: 120       # seconds
cve_inventory_binary_timeout: 60     # seconds
cve_inventory_binary_scan_paths:
  - /usr/local/bin
  - /opt
  - /srv
cve_inventory_exclude_paths:
  - /proc
  - /sys
  - /dev
  - /run
  - /tmp
  - /var/tmp
  - /boot
```

---

### Merge task (runs on localhost after all hosts complete)

After all hosts have written their `inventory/<hostname>.json` files, run a final task
on `localhost` that:
1. Reads all `inventory/*.json` files.
2. Wraps them in the top-level schema structure (adding `schema_version`, `generated_at`, `collector`).
3. Writes the merged output to `inventory.json` in the playbook directory.
4. Prints a summary: total hosts, total components by type.

---

### Example invocation

```bash
# Run against all hosts in the 'app_servers' group
ansible-playbook inventory_collector.yml \
  -i hosts.ini \
  -l app_servers \
  --become

# Run against a single host for testing
ansible-playbook inventory_collector.yml \
  -i hosts.ini \
  -l rhel8-app-01 \
  --become \
  -e "cve_inventory_jar_timeout=30"

# The merged output is then used by the CVE analyzer:
python3 cve_analyzer.py CVE-2021-44228 CVE-2023-38408 \
  --inventory inventory.json \
  --no-nist \
  -o report.csv
```

---

### Acceptance criteria

The generated playbook is considered correct when:

1. Running against a RHEL 8 host with `java-1.8.0-openjdk` installed via RPM produces
   a component entry with `type: rpm`, `detection_confidence: high`.
2. Running against a host with `/opt/myapp/lib/log4j-core-2.14.1.jar` produces
   a component entry with `name: log4j-core`, `version: 2.14.1`, `type: jar`,
   `detection_confidence: medium`.
3. Running against a host with a custom binary at `/opt/app/bin/worker` that outputs
   `worker 2.3.1` for `--version` produces `type: binary`, `version: 2.3.1`,
   `detection_confidence: low`.
4. The merged `inventory.json` validates against `inventory_schema.json`.
5. Total playbook runtime on a host with ~500 RPMs and ~20 JARs is under 10 minutes.
6. Playbook completes successfully even when `go`, `jq`, or `unzip` are absent.
