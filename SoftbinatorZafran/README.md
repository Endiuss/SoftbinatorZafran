# CrowdStrike → Zafran Integration

This project implements a **Starlark-based integration** that pulls **assets (devices)** and **Spotlight vulnerabilities** from CrowdStrike and ingests them into **Zafran** using Zafran’s public custom integrations framework.


---

## Overview

The integration performs the following high-level steps:

1. Authenticate to CrowdStrike using **OAuth2 client credentials**
2. Fetch all devices (hosts) and map them to **Zafran InstanceData**
3. Stream Spotlight vulnerabilities and map them to **Zafran Vulnerability**
4. Periodically flush collected data safely
5. Emit NDJSON export lines for auditing and debugging

---

## Supported CrowdStrike APIs

- OAuth2
  - `/oauth2/token`
- Devices (Assets)
  - `/devices/queries/devices-scroll/v1`
  - `/devices/entities/devices/v2`
- Spotlight Vulnerabilities
  - `/spotlight/combined/vulnerabilities/v1`

---

## Requirements

- Zafran runner with:
  - Starlark support
  - `http`, `json`, `log`, `zafran` modules
- CrowdStrike API credentials:
  - `client_id`
  - `client_secret`
- API permissions:
  - Devices (read)
  - Spotlight Vulnerabilities (read)

---

## Configuration Parameters

The integration is configured via keyword arguments passed to `main(**kwargs)`.

### Required parameters

| Parameter | Description |
|---------|-------------|
| `api_url` | CrowdStrike API base URL (e.g. `https://api.us-2.crowdstrike.com`) |
| `api_key` | CrowdStrike OAuth2 `client_id` |
| `api_secret` | CrowdStrike OAuth2 `client_secret` |

### Optional parameters

| Parameter | Default | Description |
|---------|---------|-------------|
| `vuln_filter` | `updated_timestamp:>'1970-01-01'` | FQL filter used when querying Spotlight vulnerabilities |

---

## Execution Flow

### 1. Authentication

- Performs OAuth2 **client-credentials** authentication.
- Retrieves a bearer token used for all subsequent API calls.
- Execution stops immediately if authentication fails.

---

### 2. Device (Asset) Collection

#### 2.1 Enumerate device IDs
- Uses `devices-scroll/v1` to retrieve **all device AIDs** via cursor-based pagination.

#### 2.2 Fetch device details
- Device AIDs are fetched in bulk using `devices/entities/devices/v2`.
- Requests are chunked to avoid payload limits.

#### 2.3 Instance mapping
Each CrowdStrike device is mapped to a **Zafran InstanceData** object with:

- `instance_id` → CrowdStrike AID
- `name` → hostname (fallback to AID)
- `operating_system`
- IP addresses
- Identifiers (`CROWDSTRIKE_AID`)
- OS labels (Windows / Linux heuristic)
- Instance type: `MACHINE`

#### 2.4 Collection and export
- Instances are collected via `zafran.collect_instance()`
- Device metadata is exported as NDJSON lines:
  ```
  EXPORT_DEVICE_JSON {...}
  ```

All instance protos are stored locally to support safe flush operations later.

---

### 3. Vulnerability Collection (Spotlight)

#### 3.1 Streaming vulnerabilities
- Uses `spotlight/combined/vulnerabilities/v1`
- Pagination via `after` cursor
- Requests include facets:
  - `cve`
  - `host_info`
  - `remediation`

#### 3.2 Host matching
Each vulnerability is associated to a host via:

1. `raw["aid"]`
2. Fallback: `raw["host_info"]["aid"]`

Vulnerabilities are classified as:
- **Mapped**: host AID exists in collected instances
- **Unmapped**: missing AID or host not found in instance inventory

#### 3.3 Vulnerability mapping
Mapped vulnerabilities are converted into **Zafran Vulnerability** objects with:

- CVE identifier
- Severity and CVSS score (best-effort)
- Component (application/vendor/version)
- Remediation suggestion (if available)
- Runtime flag (`in_runtime = true`)

Mapped vulnerabilities are collected via `zafran.collect_vulnerability()` and exported as:

```
EXPORT_VULN_JSON {...}
```

Unmapped vulnerabilities are exported as:

```
UNMAPPED_VULN_JSON {...}
```

---

### 4. Safe Flush Strategy (Critical)

Zafran drops vulnerabilities if a flush occurs while instances are missing from the buffer.

To prevent this, the integration enforces the following invariant:

> **Every flush is preceded by re-collecting all instances.**

#### Flush behavior
- Every `FLUSH_EVERY` vulnerabilities:
  1. Re-collect all instances into the buffer
  2. Call `zafran.flush()`
- After vulnerability streaming completes:
  1. Re-collect all instances
  2. Final `zafran.flush()`

This guarantees **zero orphan vulnerability loss**, even on large tenants.

---

## NDJSON Output

The script prints tagged NDJSON lines to stdout:

| Prefix | Description |
|------|-------------|
| `EXPORT_DEVICE_JSON` | Normalized device metadata |
| `EXPORT_VULN_JSON` | Normalized mapped vulnerability |
| `UNMAPPED_VULN_JSON` | Vulnerability missing host association |

These are typically redirected by the runner into files for debugging or auditing.

---

## Error Handling

- HTTP errors are logged with truncated response bodies
- Authentication failures abort execution
- Pagination failures stop the affected phase
- Mapping failures do not stop the run; they emit `UNMAPPED_VULN_JSON`

---

## Scalability Characteristics

- Supports tens of thousands of devices and vulnerabilities
- Chunked POST requests to avoid payload limits
- Streaming vulnerability ingestion with periodic flushes
- Memory footprint bounded by instance inventory size

---

## Key Design Invariants

1. **OAuth token must cover both Devices and Spotlight scopes**
2. **Instances must be present during every flush**
3. **CrowdStrike AID is the sole join key between assets and vulnerabilities**

Breaking any of these invariants will result in partial ingestion or dropped findings.

---

## Summary

This integration provides:

- Correct, loss-free ingestion of CrowdStrike assets and vulnerabilities
- Stable behavior on large datasets
- Explicit NDJSON audit trails
- Clean separation between collection, mapping, and flushing

It is suitable for **production deployments** in Zafran environments with large or complex CrowdStrike tenants.
