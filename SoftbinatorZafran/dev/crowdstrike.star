load("http", "http")
load("json", "json")
load("log", "log")
load("zafran", "zafran")

# ==============================================================================
# CrowdStrike → Zafran integration
# Output tokens (consumed by start_crowdstrike.sh awk):
#   EXPORT_DEVICE_JSON <json>
#   EXPORT_VULN_JSON   <json>   # LEGACY format (cve/first_seen/last_seen/package/score/...)
#   UNMAPPED_VULN_JSON <json>
#
# Key behavior:
# - Devices are fetched with device_filter/device_sort.
# - Spotlight vulns are fetched with vuln_filter/vuln_sort/vuln_facets PLUS an AID OR clause
#   built from the collected device ids, in chunks (Path A).
# - Export format for vulns is the "old/legacy" schema you requested.
#
# Param parsing constraint:
# - Runner parses "-params" as "k=v,k=v" → commas inside values break parsing.
# - start.sh should escape commas as "__OR__" (and "__OR__" as "__OR_ESC__")
# - this script restores them via _decode_fql()
# ==============================================================================

# -------------------------------
# Defaults / knobs
# -------------------------------
DEFAULT_DEVICES_LIMIT = 5000
DEFAULT_VULNS_LIMIT = 1000
DEFAULT_FLUSH_EVERY = 5000

DEFAULT_DEVICE_FILTER = ""
DEFAULT_DEVICE_SORT = ""

DEFAULT_VULN_FILTER = "updated_timestamp:>'1970-01-01'"
DEFAULT_VULN_SORT = ""
DEFAULT_VULN_FACETS = "cve,host_info,remediation"

# Path A knobs
DEFAULT_VULN_MUST_MATCH_DEVICES = True
AID_FILTER_CHUNK = 150  # adjust if URL length issues

ERR_BODY_TRUNC = 800

# -------------------------------
# Basic helpers
# -------------------------------
def _to_str(x):
    if x == None:
        return ""
    return str(x)

def _lower(s):
    if s == None:
        return ""
    return str(s).lower()

def _truncate(s, n):
    if s == None:
        return ""
    s2 = str(s)
    if len(s2) <= n:
        return s2
    return s2[:n] + "…"

def _decode_fql(s):
    if s == None or s == "":
        return ""
    # Undo start.sh escaping
    s = s.replace("__OR_ESC__", "__OR__")
    s = s.replace("__OR__", ",")
    return s

def _parse_bool(s, default):
    if s == None:
        return default
    v = _lower(_to_str(s))
    if v == "":
        return default
    if v in ["true", "1", "yes", "y", "on"]:
        return True
    if v in ["false", "0", "no", "n", "off"]:
        return False
    return default

def _is_int_string(s):
    if s == None or s == "":
        return False
    i = 0
    while i < len(s):
        c = s[i]
        if c < "0" or c > "9":
            return False
        i = i + 1
    return True

def _parse_int_no_try(s, default):
    if s == None:
        return default
    st = str(s)
    if st == "":
        return default
    neg = False
    if st[0] == "-":
        neg = True
        st = st[1:]
    if st == "" or not _is_int_string(st):
        return default
    n = 0
    i = 0
    while i < len(st):
        n = (n * 10) + (ord(st[i]) - 48)
        i = i + 1
    if neg:
        n = -n
    return n

def _looks_windows(os_str):
    return ("windows" in _lower(os_str))

def _looks_linux(os_str):
    s = _lower(os_str)
    return ("linux" in s) or ("ubuntu" in s) or ("debian" in s) or ("centos" in s) or ("rhel" in s) or ("red hat" in s) or ("amazon linux" in s) or ("amzn" in s)

def _chunk(xs, n):
    out = []
    i = 0
    while i < len(xs):
        out.append(xs[i:i + n])
        i = i + n
    return out

# -------------------------------
# URL helpers
# -------------------------------
def _url_encode(s):
    if s == None:
        return ""
    out = ""
    i = 0
    while i < len(s):
        c = s[i]
        o = ord(c)
        # unreserved: ALPHA / DIGIT / "-" / "." / "_" / "~"
        if (o >= 48 and o <= 57) or (o >= 65 and o <= 90) or (o >= 97 and o <= 122) or c in ["-", ".", "_", "~"]:
            out = out + c
        elif c == " ":
            out = out + "%20"
        else:
            hexchars = "0123456789ABCDEF"
            out = out + "%" + hexchars[(o // 16)] + hexchars[(o % 16)]
        i = i + 1
    return out

def _build_url(base, path, params):
    base2 = base[:-1] if base.endswith("/") else base
    url = base2 + path
    if params == None:
        return url

    parts = []
    for k in params:
        v = params[k]
        if type(v) == "list":
            j = 0
            while j < len(v):
                parts.append(_url_encode(str(k)) + "=" + _url_encode(str(v[j])))
                j = j + 1
        else:
            parts.append(_url_encode(str(k)) + "=" + _url_encode(str(v)))

    if len(parts) == 0:
        return url
    return url + "?" + "&".join(parts)

# -------------------------------
# HTTP response adapters (dict OR struct)
# -------------------------------
def _resp_status(res):
    if res == None:
        return 0
    if type(res) == "dict":
        v = res.get("status_code", 0)
        if v == None:
            return 0
        return v
    return res.status_code

def _resp_text(res):
    if res == None:
        return ""
    if type(res) == "dict":
        t = res.get("text", None)
        if t != None:
            return str(t)
        b = res.get("body", None)
        if b != None:
            return str(b)
        return ""
    return _to_str(res.text)

def _resp_json(res):
    if res == None:
        return None
    if type(res) == "dict":
        j = res.get("json", None)
        if j != None:
            return j
        raw = _resp_text(res)
        if raw == "":
            return None
        return json.decode(raw)
    return res.json()

def _http_get(url, headers):
    res = http.get(url, headers=headers)
    if res == None:
        log.error("HTTP GET failed (no response):", url)
        return None

    code = _resp_status(res)
    if code < 200 or code >= 300:
        body = _truncate(_resp_text(res), ERR_BODY_TRUNC)
        log.error("HTTP GET failed:", code, url, "body:", body)
        return None

    return _resp_json(res)

def _http_post_form(url, headers, body):
    res = http.post(url, headers=headers, body=body)
    if res == None:
        log.error("HTTP POST failed (no response):", url)
        return None

    code = _resp_status(res)
    if code < 200 or code >= 300:
        body2 = _truncate(_resp_text(res), ERR_BODY_TRUNC)
        log.error("HTTP POST failed:", code, url, "body:", body2)
        return None

    return _resp_json(res)

# -------------------------------
# OAuth2 (CrowdStrike)
# -------------------------------
def get_bearer_token(api_url, client_id, client_secret):
    log.info("Authenticating to CrowdStrike")
    url = _build_url(api_url, "/oauth2/token", None)
    body = "client_id=" + _url_encode(client_id) + "&client_secret=" + _url_encode(client_secret)
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}

    data = _http_post_form(url, headers, body)
    if data == None:
        log.error("OAuth2 token call returned no JSON")
        return ""

    token = data.get("access_token", "") or ""
    if token == "":
        log.error("OAuth2 token response missing access_token")
        return ""

    log.info("Auth OK")
    return token

# -------------------------------
# Export tokens
# -------------------------------
def export_device_ndjson(meta):
    print("EXPORT_DEVICE_JSON " + json.encode(meta))

def export_vuln_ndjson(meta):
    print("EXPORT_VULN_JSON " + json.encode(meta))

def export_unmapped_vuln_ndjson(raw):
    print("UNMAPPED_VULN_JSON " + json.encode(raw))

# -------------------------------
# Devices (combined)
# -------------------------------
def fetch_devices_combined(api_url, bearer, device_filter, device_sort, devices_limit):
    headers = {"Authorization": "Bearer " + bearer, "Accept": "application/json"}

    devices = []
    offset = ""
    page = 0

    base_params = {"limit": str(devices_limit)}
    if device_filter != "":
        base_params["filter"] = device_filter
    if device_sort != "":
        base_params["sort"] = device_sort

    while True:
        params = {}
        for k in base_params:
            params[k] = base_params[k]
        if offset != "":
            params["offset"] = offset

        url = _build_url(api_url, "/devices/combined/devices/v1", params)
        data = _http_get(url, headers)
        if data == None:
            break

        resources = data.get("resources", []) or []
        devices.extend(resources)
        page = page + 1
        log.info("Devices page", page, "got", len(resources), "(total so far", len(devices), ")")

        meta = data.get("meta", {}) or {}
        pagination = meta.get("pagination", {}) or {}
        next_off = pagination.get("next", "") or ""
        if next_off == "":
            break
        offset = next_off

    return devices

# -------------------------------
# Proto mapping: InstanceData (example.star style)
# -------------------------------
def device_to_instance(raw, pb):
    if raw == None:
        return None

    device_id = raw.get("device_id", "") or ""
    if device_id == "":
        device_id = raw.get("aid", "") or ""
    if device_id == "":
        return None

    hostname = raw.get("hostname", "") or ""
    if hostname == "":
        hostname = raw.get("device_name", "") or ""
    if hostname == "":
        hostname = device_id

    platform_name = raw.get("platform_name", "") or ""
    os_version = raw.get("os_version", "") or ""
    os_str = os_version if os_version != "" else platform_name

    ips = []
    local_ip = raw.get("local_ip", "") or ""
    if local_ip != "":
        ips.append(local_ip)
    external_ip = raw.get("external_ip", "") or ""
    if external_ip != "" and external_ip != local_ip:
        ips.append(external_ip)

    labels = []
    if _looks_windows(os_str):
        labels.append(pb.InstanceLabel(label="Windows"))
    elif _looks_linux(os_str):
        labels.append(pb.InstanceLabel(label="Linux"))

    key_value_tags = []
    cid = raw.get("cid", "") or ""
    if cid != "":
        key_value_tags.append(pb.InstanceTagKeyValue(key="crowdstrike_cid", value=cid))

    return pb.InstanceData(
        instance_id=device_id,
        name=hostname,
        operating_system=os_str,
        asset_information=pb.AssetInstanceInformation(
            ip_addresses=ips,
            mac_addresses=[]
        ),
        identifiers=[],
        labels=labels,
        key_value_tags=key_value_tags
    )

def instance_to_export_meta(inst):
    ips = []
    labels = []
    tags = {}

    if inst.asset_information != None and inst.asset_information.ip_addresses != None:
        ips = inst.asset_information.ip_addresses

    if inst.labels != None:
        i = 0
        while i < len(inst.labels):
            labels.append(inst.labels[i].label)
            i = i + 1

    if inst.key_value_tags != None:
        j = 0
        while j < len(inst.key_value_tags):
            kv = inst.key_value_tags[j]
            if kv != None and kv.key != None and kv.key != "" and kv.value != None and kv.value != "":
                tags[kv.key] = kv.value
            j = j + 1

    return {
        "hostname": inst.name,
        "instance_id": inst.instance_id,
        "ips": ips,
        "labels": labels,
        "os": inst.operating_system,
        "tags": tags,
    }

# -------------------------------
# Spotlight parsing (CVE + misconfig)
# -------------------------------
def _coerce_number(x):
    if x == None:
        return None
    t = type(x)
    if t == "int" or t == "float":
        return x

    s = str(x)
    if s == "":
        return None

    dot = False
    i = 0
    while i < len(s):
        c = s[i]
        if c == ".":
            if dot:
                return None
            dot = True
        elif c < "0" or c > "9":
            return None
        i = i + 1

    if not dot:
        return _parse_int_no_try(s, None)

    parts = s.split(".")
    if len(parts) != 2:
        return None

    a = _parse_int_no_try(parts[0], None)
    b = _parse_int_no_try(parts[1], None)
    if a == None or b == None:
        return None

    denom = 1
    j = 0
    while j < len(parts[1]):
        denom = denom * 10
        j = j + 1

    return float(a) + (float(b) / float(denom))

def _extract_finding_id(raw):
    # Prefer CVE ID; fall back to CrowdStrike internal IDs for misconfig findings.
    cve = raw.get("cve", None)
    if cve != None:
        cid = cve.get("id", "") or ""
        if cid != "":
            return cid

    vid = raw.get("vulnerability_id", "") or ""
    if vid != "":
        return vid

    vid2 = raw.get("vulnerability_metadata_id", "") or ""
    if vid2 != "":
        return vid2

    return ""

def _extract_aid(raw):
    aid = raw.get("aid", "") or ""
    if aid != "":
        return aid
    host_info = raw.get("host_info", None)
    if host_info != None:
        return host_info.get("aid", "") or ""
    return ""

def spotlight_to_vulnerability(raw, pb):
    if raw == None:
        return None

    aid = _extract_aid(raw)
    if aid == "":
        return None

    finding_id = _extract_finding_id(raw)
    if finding_id == "":
        return None

    cve = raw.get("cve", None)

    base_score = None
    vector = ""
    desc = ""
    if cve != None:
        base_score = _coerce_number(cve.get("base_score", None))
        vector = cve.get("vector", "") or ""
        desc = cve.get("description", "") or ""

    # Component as a product string (kept minimal for proto; legacy export uses raw apps too)
    prod = ""
    apps = raw.get("apps", None)
    if apps != None and type(apps) == "list" and len(apps) > 0 and apps[0] != None:
        a0 = apps[0]
        # Prefer "product_name_version" (often already includes version)
        prod = a0.get("product_name_version", "") or ""
        if prod == "":
            # Else combine name + version if present
            pn = a0.get("product_name", "") or ""
            pv = a0.get("product_version", "") or ""
            if pn != "" and pv != "":
                prod = pn + " " + pv
            elif pn != "":
                prod = pn

    # CVSS list if score exists
    cvss_list = []
    if base_score != None:
        cvss_list.append(pb.CVSS(
            base_score=float(base_score),
            vector=vector,
            version="3.0"
        ))

    # remediation suggestion
    fix = ""
    remediation = raw.get("remediation", None)
    if remediation != None:
        ents = remediation.get("entities", None)
        if ents != None and type(ents) == "list" and len(ents) > 0 and ents[0] != None:
            fix = ents[0].get("action", "") or ""
            if fix == "":
                fix = ents[0].get("title", "") or ""

    return pb.Vulnerability(
        instance_id=aid,
        cve=finding_id,  # CVE-* or CS-* id
        description=desc,
        in_runtime=True,
        component=pb.Component(
            product=prod,
            vendor="",
            version="",
            type=pb.ComponentType.LIBRARY
        ),
        CVSS=cvss_list,
        remediation=pb.Remediation(
            suggestion=fix,
            source="CrowdStrike Spotlight"
        )
    )

# -------------------------------
# LEGACY vuln NDJSON export (old format)
# -------------------------------
def _extract_package_from_raw(raw):
    # Returns (name, version) best-effort
    name = ""
    version = ""

    apps = raw.get("apps", None)
    if apps != None and type(apps) == "list" and len(apps) > 0 and apps[0] != None:
        a0 = apps[0]

        # Try to keep "name" as "product_name + product_version" when available
        pn = a0.get("product_name", "") or ""
        pv = a0.get("product_version", "") or ""

        if pn != "" and pv != "":
            name = pn + " " + pv
            version = pv
            return (name, version)

        # Fall back to product_name_version (often includes both)
        pnv = a0.get("product_name_version", "") or ""
        if pnv != "":
            name = pnv
            # no clean version; keep same to avoid empty
            version = pnv
            return (name, version)

        # last fallback
        pn2 = a0.get("product_name_normalized", "") or ""
        if pn2 != "":
            name = pn2
            version = pn2
            return (name, version)

    return (name, version)

def vuln_to_export_meta_legacy(vuln, raw, instance_proto_by_id):
    inst = instance_proto_by_id.get(vuln.instance_id, None)

    hostname = ""
    if inst != None:
        hostname = inst.name

    first_seen = raw.get("created_timestamp", "") or ""
    last_seen = raw.get("updated_timestamp", "") or ""

    (pkg_name, pkg_version) = _extract_package_from_raw(raw)

    # score + severity from raw["cve"] when present
    score = None
    severity = ""
    cve = raw.get("cve", None)
    if cve != None:
        score = cve.get("base_score", None)
        if score == None:
            score = _coerce_number(cve.get("base_score", None))
        severity = cve.get("severity", "") or ""

    status = raw.get("status", "open") or "open"

    return {
        "cve": vuln.cve,
        "first_seen": first_seen,
        "hostname": hostname,
        "instance_id": vuln.instance_id,
        "last_seen": last_seen,
        "package": {
            "name": pkg_name,
            "version": pkg_version,
        },
        "score": score,
        "severity": severity,
        "status": status,
    }

# -------------------------------
# Path A: build AID filter chunks
# -------------------------------
def _aid_or_clause(aids):
    # FQL OR is comma:
    #   aid:'a',aid:'b'
    parts = []
    i = 0
    while i < len(aids):
        parts.append("aid:'" + aids[i] + "'")
        i = i + 1
    return ",".join(parts)

def _combine_filters(base_filter, aid_clause):
    # AND is '+'
    if base_filter == "":
        return "(" + aid_clause + ")"
    return "(" + base_filter + ")+(" + aid_clause + ")"

# -------------------------------
# Flush helper: re-collect instances before flush
# -------------------------------
def _recollect_instances_for_flush(instance_proto_by_id):
    for aid in instance_proto_by_id:
        zafran.collect_instance(instance_proto_by_id[aid])

# -------------------------------
# Main
# -------------------------------
def main(**kwargs):
    api_url = kwargs.get("api_url", "https://api.crowdstrike.com")
    api_key = kwargs.get("api_key", "")
    api_secret = kwargs.get("api_secret", "")

    device_filter = _decode_fql(kwargs.get("device_filter", DEFAULT_DEVICE_FILTER))
    device_sort = _decode_fql(kwargs.get("device_sort", DEFAULT_DEVICE_SORT))

    vuln_filter = _decode_fql(kwargs.get("vuln_filter", DEFAULT_VULN_FILTER))
    vuln_sort = _decode_fql(kwargs.get("vuln_sort", DEFAULT_VULN_SORT))
    facets_raw = _decode_fql(kwargs.get("vuln_facets", DEFAULT_VULN_FACETS))

    devices_limit = _parse_int_no_try(kwargs.get("devices_limit", DEFAULT_DEVICES_LIMIT), DEFAULT_DEVICES_LIMIT)
    if devices_limit <= 0:
        devices_limit = DEFAULT_DEVICES_LIMIT

    vulns_limit = _parse_int_no_try(kwargs.get("vulns_limit", DEFAULT_VULNS_LIMIT), DEFAULT_VULNS_LIMIT)
    if vulns_limit <= 0:
        vulns_limit = DEFAULT_VULNS_LIMIT

    flush_every = _parse_int_no_try(kwargs.get("flush_every", DEFAULT_FLUSH_EVERY), DEFAULT_FLUSH_EVERY)
    if flush_every <= 0:
        flush_every = DEFAULT_FLUSH_EVERY

    include_unmapped = _parse_bool(kwargs.get("include_unmapped", True), True)

    vuln_must_match_devices = _parse_bool(kwargs.get("vuln_must_match_devices", None), None)
    if vuln_must_match_devices == None:
        vuln_must_match_devices = (device_filter != "")

    facet_list = []
    if facets_raw != "":
        parts = facets_raw.split(",")
        i = 0
        while i < len(parts):
            p = parts[i].strip()
            if p != "":
                facet_list.append(p)
            i = i + 1

    log.info("API URL :", api_url)
    log.info("Devices: limit=", devices_limit, "filter=", (device_filter if device_filter != "" else "<none>"), "sort=", (device_sort if device_sort != "" else "<none>"))
    log.info("Vulns  : limit=", vulns_limit, "filter=", vuln_filter, "sort=", (vuln_sort if vuln_sort != "" else "<none>"), "facets=", facet_list)
    log.info("Ops    : flush_every=", flush_every, "include_unmapped=", include_unmapped, "vuln_must_match_devices=", vuln_must_match_devices)

    pb = zafran.proto_file

    bearer = get_bearer_token(api_url, api_key, api_secret)
    if bearer == "":
        log.error("Authentication failed (empty bearer token)")
        return None

    # -------------------------
    # Devices → Instances
    # -------------------------
    raw_devices = fetch_devices_combined(api_url, bearer, device_filter, device_sort, devices_limit)
    log.info("Instances fetched:", len(raw_devices))

    instance_proto_by_id = {}
    aids = []

    i = 0
    while i < len(raw_devices):
        inst = device_to_instance(raw_devices[i], pb)
        if inst != None:
            instance_proto_by_id[inst.instance_id] = inst
            aids.append(inst.instance_id)

            zafran.collect_instance(inst)
            export_device_ndjson(instance_to_export_meta(inst))
        i = i + 1

    log.info("Instances collected:", len(instance_proto_by_id))

    # -------------------------
    # Spotlight vulnerabilities (paged) — Path A
    # -------------------------
    headers = {"Authorization": "Bearer " + bearer, "Accept": "application/json"}

    total = 0
    vulns_collected = 0
    unmapped = 0
    missing_aid = 0

    aid_chunks = [aids]
    if vuln_must_match_devices:
        aid_chunks = _chunk(aids, AID_FILTER_CHUNK)

    chunk_idx = 0
    while chunk_idx < len(aid_chunks):
        vf = vuln_filter
        if vuln_must_match_devices:
            clause = _aid_or_clause(aid_chunks[chunk_idx])
            vf = _combine_filters(vuln_filter, clause)

        after = ""
        page = 0

        while True:
            params = {"limit": str(vulns_limit), "filter": vf}
            if vuln_sort != "":
                params["sort"] = vuln_sort
            if len(facet_list) > 0:
                params["facet"] = facet_list
            if after != "":
                params["after"] = after

            url = _build_url(api_url, "/spotlight/combined/vulnerabilities/v1", params)
            data = _http_get(url, headers)
            if data == None:
                break

            resources = data.get("resources", []) or []
            page = page + 1
            got = len(resources)
            total = total + got
            log.info("Vulns chunk", (chunk_idx + 1), "/", len(aid_chunks), "page", page, "got", got, "(total so far", total, ")")

            if got == 0:
                break

            j = 0
            while j < got:
                raw = resources[j]

                vuln = spotlight_to_vulnerability(raw, pb)
                if vuln == None:
                    aid2 = _extract_aid(raw)
                    if aid2 == "":
                        missing_aid = missing_aid + 1
                    else:
                        unmapped = unmapped + 1

                    if include_unmapped:
                        export_unmapped_vuln_ndjson(raw)

                    j = j + 1
                    continue

                # Safety check (should not happen if Path A is correct)
                if vuln_must_match_devices and (vuln.instance_id not in instance_proto_by_id):
                    if include_unmapped:
                        export_unmapped_vuln_ndjson(raw)
                    j = j + 1
                    continue

                zafran.collect_vulnerability(vuln)

                # LEGACY export format
                export_vuln_ndjson(vuln_to_export_meta_legacy(vuln, raw, instance_proto_by_id))

                vulns_collected = vulns_collected + 1

                if flush_every > 0 and (vulns_collected % flush_every) == 0:
                    _recollect_instances_for_flush(instance_proto_by_id)
                    zafran.flush()
                    log.info("Flushed at vulns_collected=", vulns_collected)

                j = j + 1

            meta = data.get("meta", {}) or {}
            pagination = meta.get("pagination", {}) or {}
            after_next = pagination.get("after", "") or ""
            if after_next == "":
                break
            after = after_next

        chunk_idx = chunk_idx + 1

    _recollect_instances_for_flush(instance_proto_by_id)
    zafran.flush()

    log.info("Done. Instances:", len(instance_proto_by_id),
             "Vulns collected:", vulns_collected,
             "Unmapped:", unmapped,
             "Missing aid:", missing_aid)
    return None

# -------------------------------
# REPL helpers
# -------------------------------
def repl_smoke(api_url, api_key, api_secret):
    bearer = get_bearer_token(api_url, api_key, api_secret)
    if bearer == "":
        return None
    headers = {"Authorization": "Bearer " + bearer, "Accept": "application/json"}
    url = _build_url(api_url, "/devices/combined/devices/v1", {"limit": "1"})
    data = _http_get(url, headers)
    if data == None:
        log.error("repl_smoke failed: cannot query devices")
        return None
    got = len(data.get("resources", []) or [])
    log.info("repl_smoke OK: devices resources:", got)
    return None

def show_collected():
    print(zafran.show_collected())
    return None

def repl_run_full_from_params(**params):
    return main(**params)
