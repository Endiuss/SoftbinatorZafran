## CrowdStrike → Zafran Custom Integration

This repository provides a production‑grade **CrowdStrike Falcon Spotlight integration** for **Zafran**, implemented in **Starlark** and designed for correctness, safety, and reproducibility.

The integration collects:
- **Assets / devices** from CrowdStrike Falcon
- **Vulnerabilities & misconfigurations** from Falcon Spotlight

while enforcing **strict device‑scoped vulnerability collection** and offering **full user control via FQL filters**.

---

## Key Features

### 1. Device‑scoped vulnerability collection 

1. Devices are collected first using the provided device filter
2. Device IDs (AIDs) are extracted
3. Spotlight queries are constrained to those AIDs

This guarantees:
- No tenant‑wide leakage
- Every vulnerability maps to a collected device
- Strong referential integrity between devices and vulnerabilities

---

### 2. User‑controlled FQL filtering (no URL encoding)
Users can pass **raw CrowdStrike FQL** directly from the CLI:

- Device filters (`--device-filter`, `--device-sort`)
- Vulnerability filters (`--vuln-filter`, `--vuln-sort`, `--vuln-facets`)

No URL encoding (`%3A`, `%27`, etc.) is required.
A wrapper script safely escapes parameters before passing them to the runner.

---

### 3. Legacy vulnerability NDJSON output (backward compatible)
Vulnerabilities are exported in the **legacy NDJSON format**:

```json
{
  "cve": "CVE-2024-21853",
  "first_seen": "2025-11-21T14:02:54Z",
  "hostname": "example-host",
  "instance_id": "<aid>",
  "last_seen": "2025-11-23T03:01:53Z",
  "package": {
    "name": "openssl 3.0.2",
    "version": "3.0.2"
  },
  "score": 7.5,
  "severity": "HIGH",
  "status": "open"
}
```

Proto collection is still performed internally for Zafran ingestion; only the
export format is legacy.

---

### 4. Robust pagination & flushing
- Supports large tenants via paginated API calls
- Periodic flushing with instance re‑collection to preserve context
- Safe handling of unmapped / malformed Spotlight findings

---

## Repository Structure

```text
.
├── start.sh                  # User‑facing CLI wrapper
├── start_crowdstrike.sh      # Runner invocation + NDJSON extraction
├── dev/
│   └── crowdstrike.star      # Main Starlark integration
├── output/                   # Generated NDJSON + logs
├── test_runs_time_*          # Automated time‑filter test results
└── run_time_tests.sh         # Time‑filter regression tests
```

---

## Authentication (OAuth2)

CrowdStrike APIs use **OAuth2 Client Credentials**. The integration authenticates by calling:

- `POST /oauth2/token`
- form body: `client_id=<API_KEY>&client_secret=<API_SECRET>`
- response: `access_token`

The script then adds the header to all subsequent API calls:

- `Authorization: Bearer <access_token>`

### Required credentials

You must provide a **CrowdStrike API client** (client_id / client_secret) with permissions for:
- Device inventory (Falcon Discover / Hosts)
- Spotlight vulnerabilities

(Exact permission names vary by tenant; ensure the client can call the endpoints used below.)

---

## Usage

### Environment variables

```bash
export API_URL="https://api.us-2.crowdstrike.com"
export API_KEY="<client_id>"
export API_SECRET="<client_secret>"
```

### Minimal run

```bash
./start.sh \
  --device-filter "platform_name:'Windows'" \
  --vuln-filter "updated_timestamp:>'now-7d'"
```

### Full example

```bash
./start.sh \
  --device-filter "platform_name:'Windows'" \
  --device-sort "hostname.asc" \
  --devices-limit 5000 \
  --vuln-filter "updated_timestamp:>'now-7d'" \
  --vuln-sort "updated_timestamp.desc" \
  --vuln-facets "cve,host_info,remediation" \
  --vulns-limit 200 \
  --flush-every 200
```

---

## Automated time‑filter tests

A regression test runner validates time‑based filtering semantics:

```bash
./run_time_tests.sh
```

Tests include:
- Monotonic windows (`now-1d ⊆ now-7d ⊆ now-30d`)
- Bounded ranges (`now-7d` to `now-1d`)
- Future windows (must return zero results)
- `created_timestamp` vs `updated_timestamp` behavior

Each test run is written to its own folder with PASS/FAIL summaries.

---

## Guarantees

- No vulnerability is emitted without a matching device
- Filters are passed verbatim to CrowdStrike (no silent widening)
- Sorting and pagination are applied server‑side
- Output format remains stable for existing consumers

---

