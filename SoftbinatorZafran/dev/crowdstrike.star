load("http", "http")
load("json", "json")
load("log", "log")
load("zafran", "zafran")

# =====================================================================
# CrowdStrike → Zafran integration
#
# This script:
#   - Authenticates to CrowdStrike (OAuth2 client credentials)
#   - Collects devices as Zafran InstanceData
#   - Collects Spotlight vulnerabilities as Zafran Vulnerability
#   - Prints NDJSON export lines (EXPORT_DEVICE_JSON / EXPORT_VULN_JSON / UNMAPPED_VULN_JSON)
#   - Supports large datasets with periodic flushing (re-collect instances before each flush)
#   - Supports REPL helpers for interactive testing
# =====================================================================

# -------------------------------
# Tunables / Constants
# -------------------------------

# CrowdStrike Spotlight requires a filter in many contexts.
# Default here means "everything since epoch" (effectively all records available).
DEFAULT_VULN_FILTER = "updated_timestamp:>'1970-01-01'"  # str: FQL filter used for vulnerabilities fetch (can be overridden via params)

# Devices scroll page size. Higher -> fewer API calls, larger response.
DEVICES_SCROLL_LIMIT = 5000  # int: max number of device AIDs per devices-scroll page

# Chunk size for POST /devices/entities/devices/v2 (ids list). Higher -> fewer calls, but request payload larger.
DEVICES_DETAILS_CHUNK = 5000  # int: number of AIDs per details POST call

# Spotlight vulnerabilities page size. Higher -> fewer API calls, larger response; may increase rate-limit risk.
VULNS_LIMIT = 1000  # int: max number of vulns per Spotlight page request

# Flush cadence for large runs. Every N collected vulns: re-collect instances + flush.
# IMPORTANT: We re-collect instances before flush to avoid "orphan vulnerabilities dropped" behavior.
FLUSH_EVERY = 5000  # int: flush every N vulnerabilities collected

# Maximum response-body length to log on errors (avoid terminal overflow).
ERR_BODY_TRUNC = 800  # int: truncate HTTP error bodies to this many chars

# -------------------------------
# Small utilities
# -------------------------------

def _truncate(s, n):
    """
    Truncate a string to at most n characters, appending a "(truncated)" suffix when cut.

    Parameters:
      s (str|None): input string (may be None)
      n (int): maximum length

    Returns:
      str: truncated string ("" if s is None)
    """
    if s == None:
        return ""
    if len(s) <= n:
        return s
    return s[:n] + "...(truncated)"

def _to_str(x):
    """
    Convert a Starlark value into a string safely.

    Parameters:
      x (any|None): input value

    Returns:
      str: string form ("" if x is None)
    """
    if x == None:
        return ""
    if type(x) == "string":
        return x
    return "%s" % x

def _lower(s):
    """
    Lowercase helper that tolerates None.

    Parameters:
      s (str|None): input string

    Returns:
      str: lowercase string ("" if None)
    """
    if s == None:
        return ""
    return str(s).lower()

def _looks_windows(platform_name, os_string):
    """
    Heuristic OS family detection: Windows.

    Parameters:
      platform_name (str|None): device platform field
      os_string (str|None): constructed OS description

    Returns:
      bool: True if windows-like
    """
    p = _lower(platform_name)
    o = _lower(os_string)
    return ("windows" in p) or ("windows" in o)

def _looks_linux(platform_name, os_string):
    """
    Heuristic OS family detection: Linux.

    Parameters:
      platform_name (str|None): device platform field
      os_string (str|None): constructed OS description

    Returns:
      bool: True if linux-like
    """
    p = _lower(platform_name)
    o = _lower(os_string)
    return ("linux" in p) or ("linux" in o) or ("ubuntu" in o) or ("debian" in o) or ("centos" in o) or ("rhel" in o) or ("red hat" in o) or ("amazon linux" in o)

def _url_encode(s):
    """
    Minimal URL-encoding suitable for query strings and x-www-form-urlencoded bodies.

    Notes:
      - This is not a full RFC-compliant encoder, but it covers the characters we use here.
      - Needed because runner's Starlark environment typically doesn't ship a full urlencode utility.

    Parameters:
      s (str|None): input string

    Returns:
      str: encoded string
    """
    if s == None:
        return ""
    s = _to_str(s)
    s = s.replace("%", "%25")
    s = s.replace(" ", "%20")
    s = s.replace("'", "%27")
    s = s.replace("\"", "%22")
    s = s.replace(":", "%3A")
    s = s.replace(">", "%3E")
    s = s.replace("<", "%3C")
    s = s.replace("[", "%5B")
    s = s.replace("]", "%5D")
    s = s.replace(",", "%2C")
    s = s.replace("=", "%3D")
    s = s.replace("&", "%26")
    s = s.replace("?", "%3F")
    s = s.replace("#", "%23")
    s = s.replace("/", "%2F")
    s = s.replace("\\", "%5C")
    s = s.replace("|", "%7C")
    s = s.replace("{", "%7B")
    s = s.replace("}", "%7D")
    s = s.replace("(", "%28")
    s = s.replace(")", "%29")
    s = s.replace("!", "%21")
    s = s.replace("+", "%2B")
    s = s.replace("@", "%40")
    s = s.replace("$", "%24")
    return s

def _build_url(api_url, path, params):
    """
    Build a full URL from base API URL, a path, and optional query parameters.

    Supports list-values for repeated parameters:
      {"facet": ["cve", "host_info"]} -> facet=cve&facet=host_info

    Parameters:
      api_url (str): base CrowdStrike API URL, e.g. https://api.us-2.crowdstrike.com
      path (str): endpoint path, e.g. /oauth2/token
      params (dict|None): map of query parameters. Values may be string/int/bool or list.

    Returns:
      str: full URL including query string
    """
    base = api_url.rstrip("/")
    url = base + path
    if params == None or len(params) == 0:
        return url

    qs = []
    for k in params:
        v = params[k]
        if v == None:
            continue

        if type(v) == "list":
            i = 0
            while i < len(v):
                vv = v[i]
                if vv != None:
                    qs.append(_url_encode(k) + "=" + _url_encode(vv))
                i = i + 1
        else:
            qs.append(_url_encode(k) + "=" + _url_encode(v))

    if len(qs) == 0:
        return url
    return url + "?" + "&".join(qs)

def _http_get(url, headers):
    """
    HTTP GET wrapper using runner's http module return shape.

    Behavior:
      - Expects response dict with keys: "status_code", "body"
      - On non-200: logs error (truncated body) and returns None
      - On empty body: returns {}
      - Otherwise: returns decoded JSON dict

    Parameters:
      url (str): full URL
      headers (dict): request headers

    Returns:
      dict|None: decoded JSON object, {} for empty body, None on error
    """
    resp = http.get(url, headers=headers)
    code = resp["status_code"]
    body = resp["body"]

    if code == 204:
        return {}

    if code != 200:
        log.error("HTTP GET failed:", code, "url=", url, "body=", _truncate(body, ERR_BODY_TRUNC))
        return None

    if body == None or body == "":
        return {}
    return json.decode(body)

def _http_post_form(url, headers, body):
    """
    HTTP POST wrapper for x-www-form-urlencoded payloads.

    Notes:
      - CrowdStrike /oauth2/token can return 200 or 201 in some environments.

    Parameters:
      url (str): full URL
      headers (dict): request headers (should include Content-Type)
      body (str): URL-encoded request body

    Returns:
      dict|None: decoded JSON object, {} for empty body, None on error
    """
    resp = http.post(url, headers=headers, body=body)
    code = resp["status_code"]
    rbody = resp["body"]

    if not (code == 200 or code == 201):
        log.error("HTTP POST failed:", code, "url=", url, "body=", _truncate(rbody, ERR_BODY_TRUNC))
        return None

    if rbody == None or rbody == "":
        return {}
    return json.decode(rbody)

def _http_post_json(url, headers, obj):
    """
    HTTP POST wrapper for JSON payloads.

    Behavior:
      - Adds Content-Type: application/json
      - On non-200: logs error (truncated body) and returns None
      - On empty body: returns {}
      - Otherwise: returns decoded JSON dict

    Parameters:
      url (str): full URL
      headers (dict): base headers (Authorization etc.)
      obj (dict): JSON-serializable object

    Returns:
      dict|None: decoded JSON object, {} for empty body, None on error
    """
    h = {}
    for k in headers:
        h[k] = headers[k]
    h["Content-Type"] = "application/json"

    body = json.encode(obj)
    resp = http.post(url, headers=h, body=body)
    code = resp["status_code"]
    rbody = resp["body"]

    if code != 200:
        log.error("HTTP POST JSON failed:", code, "url=", url, "body=", _truncate(rbody, ERR_BODY_TRUNC))
        return None

    if rbody == None or rbody == "":
        return {}
    return json.decode(rbody)

def _chunk_list(xs, chunk_size):
    """
    Split a list into consecutive chunks of size chunk_size.

    Parameters:
      xs (list): input list
      chunk_size (int): chunk size

    Returns:
      list[list]: list of chunks
    """
    out = []
    i = 0
    n = len(xs)
    while i < n:
        out.append(xs[i:i + chunk_size])
        i = i + chunk_size
    return out

# -------------------------------
# Auth
# -------------------------------

def get_bearer_token(api_url, api_key, api_secret):
    """
    Perform OAuth2 client-credentials auth to CrowdStrike and return the bearer token.

    Parameters:
      api_url (str): base CrowdStrike API URL
      api_key (str): CrowdStrike client_id
      api_secret (str): CrowdStrike client_secret

    Returns:
      str: access token on success, "" on failure
    """
    token_url = _build_url(api_url, "/oauth2/token", None)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    payload = "client_id=%s&client_secret=%s" % (_url_encode(api_key), _url_encode(api_secret))

    log.info("Authenticating to CrowdStrike")
    data = _http_post_form(token_url, headers, payload)
    if data == None:
        return ""
    token = data.get("access_token", "")
    if token == "":
        log.error("Auth failed: missing access_token. Response keys:", data.keys())
        return ""
    log.info("Auth OK")
    return token

# -------------------------------
# Devices: devices-scroll -> POST device details v2
# -------------------------------

def _fetch_device_aids_scroll(api_url, bearer):
    """
    Fetch all device AIDs using devices-scroll query endpoint (pagination via offset).

    Parameters:
      api_url (str): base CrowdStrike API URL
      bearer (str): OAuth2 bearer token

    Returns:
      list[str]: list of AIDs (device IDs)
    """
    headers = {"Authorization": "Bearer " + bearer, "Accept": "application/json"}

    aids = []
    offset = ""
    page = 0

    while True:
        params = {"limit": str(DEVICES_SCROLL_LIMIT)}
        if offset != "":
            params["offset"] = offset

        url = _build_url(api_url, "/devices/queries/devices-scroll/v1", params)
        data = _http_get(url, headers)
        if data == None:
            break

        res = data.get("resources", [])
        if res == None:
            res = []

        page = page + 1
        aids.extend(res)

        meta = data.get("meta", {})
        pag = meta.get("pagination", {}) if meta != None else {}
        next_offset = pag.get("offset", "") if pag != None else ""

        log.info("Devices scroll page:", page, "got", len(res), "total so far", len(aids))

        if len(res) == 0:
            break
        if next_offset == "" or next_offset == None:
            break

        offset = next_offset

    return aids

def fetch_instances(api_url, bearer):
    """
    Fetch full device objects for all hosts.

    Implementation:
      1) /devices/queries/devices-scroll/v1 to get AIDs
      2) /devices/entities/devices/v2 via POST {"ids":[...]} in chunks

    Parameters:
      api_url (str): base CrowdStrike API URL
      bearer (str): OAuth2 bearer token

    Returns:
      list[dict]: raw device objects (CrowdStrike JSON resources)
    """
    headers = {"Authorization": "Bearer " + bearer, "Accept": "application/json"}

    aids = _fetch_device_aids_scroll(api_url, bearer)
    if len(aids) == 0:
        return []

    instances = []
    chunks = _chunk_list(aids, DEVICES_DETAILS_CHUNK)
    log.info("Devices details fetch (POST v2): aids=", len(aids), "chunks=", len(chunks), "chunk_size=", DEVICES_DETAILS_CHUNK)

    idx = 0
    total_chunks = len(chunks)
    while idx < total_chunks:
        chunk = chunks[idx]
        url = _build_url(api_url, "/devices/entities/devices/v2", None)
        data = _http_post_json(url, headers, {"ids": chunk})
        if data != None:
            res = data.get("resources", [])
            if res == None:
                res = []
            instances.extend(res)

        log.info("Devices details progress: chunk", (idx + 1), "/", total_chunks, "resources so far", len(instances))
        idx = idx + 1

    return instances

# -------------------------------
# Instance mapping + export
# -------------------------------

def parse_to_instance(raw, pb):
    """
    Map a CrowdStrike device object into Zafran InstanceData.

    Mapping highlights:
      - instance_id = device_id / aid
      - name = hostname
      - operating_system = os_product_name or platform+version
      - ip_addresses = local_ip + external_ip (if present)
      - identifiers includes CROWDSTRIKE_AID
      - labels: Windows/Linux
      - key_value_tags: crowdstrike_cid

    Parameters:
      raw (dict): CrowdStrike device resource object
      pb (module): Zafran proto module (zafran.proto_file)

    Returns:
      pb.InstanceData|None: instance proto, or None if device_id missing
    """
    if raw == None:
        return None

    aid = raw.get("device_id", "")
    if aid == "":
        aid = raw.get("aid", "")
    if aid == "":
        aid = raw.get("id", "")
    if aid == "":
        return None

    hostname = raw.get("hostname", "")
    if hostname == "":
        hostname = raw.get("device_name", "")

    platform_name = raw.get("platform_name", "")
    os_version = raw.get("os_version", "")
    os_product_name = raw.get("os_product_name", "")

    os_str = ""
    if os_product_name != "":
        os_str = os_product_name
    elif platform_name != "" and os_version != "":
        os_str = platform_name + " " + os_version
    elif platform_name != "":
        os_str = platform_name
    else:
        os_str = os_version

    ips = []
    lip = raw.get("local_ip", "")
    eip = raw.get("external_ip", "")
    if lip != "":
        ips.append(lip)
    if eip != "" and eip != lip:
        ips.append(eip)

    cid = raw.get("cid", "")

    labels = []
    if _looks_windows(platform_name, os_str):
        labels = [pb.InstanceLabel(label="Windows")]
    elif _looks_linux(platform_name, os_str):
        labels = [pb.InstanceLabel(label="Linux")]

    kv_tags = []
    if cid != "":
        kv_tags.append(pb.InstanceTagKeyValue(key="crowdstrike_cid", value=cid))

    identifiers = [
        pb.InstanceIdentifier(
            key=pb.IdentifierType.CROWDSTRIKE_AID,
            value=aid,
        ),
    ]

    inst = pb.InstanceData(
        instance_id=aid,
        name=hostname if hostname != "" else aid,
        operating_system=os_str,
        asset_information=pb.AssetInstanceInformation(ip_addresses=ips),
        identifiers=identifiers,
        labels=labels,
        key_value_tags=kv_tags,
        instance_type=pb.InstanceType.INSTANCE_TYPE_MACHINE,
    )
    return inst

def export_device_ndjson(meta_obj):
    """
    Emit a single NDJSON line for a device export.

    Output format (stdout line contains runner prefix + this token):
      EXPORT_DEVICE_JSON {json}

    Parameters:
      meta_obj (dict): normalized device metadata

    Returns:
      None
    """
    print("EXPORT_DEVICE_JSON " + json.encode(meta_obj))

# -------------------------------
# Severity + score extraction (Starlark-safe, no try/except)
# -------------------------------

def _is_int_string(s):
    """
    Check whether a string represents an integer (optional leading + / -).

    Parameters:
      s (str|None): candidate

    Returns:
      bool
    """
    if s == None:
        return False
    if type(s) != "string":
        return False
    s = s.strip()
    if s == "":
        return False

    i = 0
    if s[0] == "-" or s[0] == "+":
        if len(s) == 1:
            return False
        i = 1

    while i < len(s):
        c = s[i]
        if c < "0" or c > "9":
            return False
        i = i + 1
    return True

def _parse_int_no_try(s):
    """
    Parse an integer string without try/except (Starlark has no exceptions).

    Parameters:
      s (str): integer string

    Returns:
      int
    """
    s = s.strip()
    sign = 1
    idx = 0
    if s[0] == "-":
        sign = -1
        idx = 1
    elif s[0] == "+":
        idx = 1

    val = 0
    while idx < len(s):
        val = val * 10 + (ord(s[idx]) - ord("0"))
        idx = idx + 1
    return sign * val

def _coerce_number(x):
    """
    Coerce values into a numeric-ish value for export.
    - int/float -> returned unchanged
    - "123" -> int
    - "9.8" -> returned as string (still informative for NDJSON)
    - others -> returned unchanged

    Parameters:
      x (any|None): input

    Returns:
      any|None
    """
    if x == None:
        return None
    t = type(x)
    if t == "int" or t == "float":
        return x
    if t == "string":
        s = x.strip()
        if _is_int_string(s):
            return _parse_int_no_try(s)
        return s
    return x

def _extract_severity(raw):
    """
    Extract vulnerability severity from Spotlight record.

    Primary source:
      raw["cve"]["severity"]  (requires facet=cve)

    Fallbacks:
      raw["severity"]

    Parameters:
      raw (dict): Spotlight vulnerability record

    Returns:
      str: severity string or ""
    """
    cve = raw.get("cve", None)
    if cve != None:
        sev = cve.get("severity", "")
        if sev != "":
            return sev
    sev = raw.get("severity", "")
    if sev != "":
        return sev
    return ""

def _extract_score(raw):
    """
    Extract CVSS base score / numeric score from Spotlight record.

    Primary source:
      raw["cve"]["base_score"]  (requires facet=cve)

    Fallbacks:
      - raw["data_providers"][0]["rating"]
      - raw["score"]

    Parameters:
      raw (dict): Spotlight vulnerability record

    Returns:
      int|float|str|None: score (depending on API payload type)
    """
    cve = raw.get("cve", None)
    if cve != None:
        bs = cve.get("base_score", None)
        if bs != None:
            return _coerce_number(bs)

    dps = raw.get("data_providers", None)
    if dps != None and type(dps) == "list" and len(dps) > 0:
        dp0 = dps[0]
        if dp0 != None:
            r = dp0.get("rating", None)
            if r != None:
                return _coerce_number(r)

    score = raw.get("score", None)
    if score != None:
        return _coerce_number(score)

    return None

# -------------------------------
# Vulnerability mapping + export
# -------------------------------

def _extract_cve_id(raw):
    """
    Pick a stable vulnerability identifier.

    Prefer:
      - raw["vulnerability_id"]
      - raw["cve"]["id"] (requires facet=cve)
    Fallback:
      - raw["id"]

    Parameters:
      raw (dict): Spotlight vulnerability record

    Returns:
      str
    """
    vid = raw.get("vulnerability_id", "")
    if vid != "":
        return vid
    cve = raw.get("cve", {})
    if cve != None:
        cid = cve.get("id", "")
        if cid != "":
            return cid
    rid = raw.get("id", "")
    return rid

def _extract_cvss_list(raw, pb):
    """
    Build Zafran CVSS list from Spotlight cve facet.

    Parameters:
      raw (dict): Spotlight vulnerability record
      pb (module): proto module

    Returns:
      list[pb.CVSS]: possibly empty list
    """
    out = []
    cve = raw.get("cve", {})
    if cve == None:
        return out
    base = cve.get("base_score", None)
    vector = cve.get("vector", "")
    ver = cve.get("version", "")
    if base == None:
        return out
    out.append(pb.CVSS(
        version=ver,
        vector=vector,
        base_score=base,
        source="crowdstrike",
        type="primary",
    ))
    return out

def _extract_component(raw, pb):
    """
    Build a Zafran Component from Spotlight fields.

    This uses best-effort fields found in Spotlight resources/apps.

    Parameters:
      raw (dict): Spotlight vulnerability record
      pb (module): proto module

    Returns:
      pb.Component
    """
    vendor = raw.get("vendor_normalized", "")
    prod_nv = raw.get("product_name_version", "")
    prod_n = raw.get("product_name_normalized", "")

    apps = raw.get("apps", [])
    if apps != None and len(apps) > 0:
        a0 = apps[0]
        if vendor == "":
            vendor = a0.get("vendor_normalized", "")
        if prod_nv == "":
            prod_nv = a0.get("product_name_version", "")
        if prod_n == "":
            prod_n = a0.get("product_name_normalized", "")

    display = prod_nv if prod_nv != "" else prod_n
    product = prod_n if prod_n != "" else display

    version = ""
    if prod_nv != "":
        parts = prod_nv.split(" ")
        if len(parts) >= 2:
            version = parts[len(parts) - 1]

    return pb.Component(
        type=pb.ComponentType.APPLICATION,
        product=product,
        vendor=vendor,
        version=version,
        display_name=display,
    )

def parse_to_vulnerability(raw, pb):
    """
    Map a CrowdStrike Spotlight record into Zafran Vulnerability.

    Mapping highlights:
      - instance_id = raw["aid"] or raw["host_info"]["aid"]
      - cve = best-effort identifier
      - CVSS populated from cve facet when available
      - remediation suggestion from remediation facet when available
      - severity populated via _extract_severity()

    Parameters:
      raw (dict): Spotlight vulnerability record
      pb (module): proto module

    Returns:
      pb.Vulnerability|None: vulnerability proto, or None if missing host aid or identifier
    """
    if raw == None:
        return None

    aid = raw.get("aid", "")
    if aid == "":
        host_info = raw.get("host_info", {})
        if host_info != None:
            aid = host_info.get("aid", "")
    if aid == "":
        return None

    cve_id = _extract_cve_id(raw)
    if cve_id == "":
        return None

    desc = ""
    cve = raw.get("cve", {})
    if cve != None:
        desc = cve.get("description", "")
    if desc == "":
        desc = raw.get("scanner_name", "")
    if desc == "":
        desc = raw.get("description", "")

    suggestion = ""
    remediation = raw.get("remediation", {})
    if remediation != None:
        ent = remediation.get("entities", None)
        if ent != None and len(ent) > 0:
            e0 = ent[0]
            if e0 != None:
                suggestion = _to_str(e0.get("action", ""))

    vuln = pb.Vulnerability(
        instance_id=aid,
        cve=cve_id,
        in_runtime=True,
        component=_extract_component(raw, pb),
        remediation=pb.Remediation(
            suggestion=suggestion,
            source="crowdstrike",
            fixed_in_version="",
        ),
        CVSS=_extract_cvss_list(raw, pb),
        description=desc,
        severity=_extract_severity(raw),
    )
    return vuln

def export_vuln_ndjson(obj):
    """
    Emit a single NDJSON line for a vulnerability export.

    Output format (stdout line contains runner prefix + this token):
      EXPORT_VULN_JSON {json}

    Parameters:
      obj (dict): normalized vulnerability metadata

    Returns:
      None
    """
    print("EXPORT_VULN_JSON " + json.encode(obj))

def export_unmapped_vuln_ndjson(obj):
    """
    Emit a single NDJSON line for an unmapped vulnerability export (missing/unknown host aid).

    Output format (stdout line contains runner prefix + this token):
      UNMAPPED_VULN_JSON {json}

    Parameters:
      obj (dict): raw Spotlight record or a normalized dict

    Returns:
      None
    """
    print("UNMAPPED_VULN_JSON " + json.encode(obj))

# -------------------------------
# Flush helper (orphan prevention)
# -------------------------------

def _recollect_instances_for_flush(instances_for_flush):
    """
    Re-collect all instances into the runner buffer prior to a flush.

    Why:
      The runner drops vulnerabilities if flush() is called when there are "orphan vulnerabilities"
      (vulns buffered without instances buffered). This function ensures each flush batch contains
      instances + vulns together.

    Parameters:
      instances_for_flush (list[pb.InstanceData]): previously-built instance protos

    Returns:
      None
    """
    log.info("Preparing flush batch: re-collecting instances for this flush:", len(instances_for_flush))
    i = 0
    n = len(instances_for_flush)
    while i < n:
        zafran.collect_instance(instances_for_flush[i])
        i = i + 1

# -------------------------------
# Main
# -------------------------------

def main(**kwargs):
    """
    Production entrypoint.

    Steps:
      1) Read params (api_url, api_key, api_secret, vuln_filter)
      2) OAuth2 authenticate and build bearer token
      3) Fetch devices and map to Zafran InstanceData
         - zafran.collect_instance(instance)
         - emit EXPORT_DEVICE_JSON lines
      4) Stream Spotlight vulnerabilities (paged)
         - map to Zafran Vulnerability
         - zafran.collect_vulnerability(vuln)
         - emit EXPORT_VULN_JSON or UNMAPPED_VULN_JSON
         - every FLUSH_EVERY: re-collect instances and flush
      5) Final re-collect + flush
      6) Summary logs

    Parameters (kwargs):
      api_url (str): base CrowdStrike API URL (default https://api.crowdstrike.com)
      api_key (str): CrowdStrike client_id
      api_secret (str): CrowdStrike client_secret
      vuln_filter (str): FQL filter for Spotlight (defaults to DEFAULT_VULN_FILTER)

    Returns:
      None
    """
    api_url = kwargs.get("api_url", "https://api.crowdstrike.com")
    api_key = kwargs.get("api_key", "")
    api_secret = kwargs.get("api_secret", "")

    vuln_filter = kwargs.get("vuln_filter", DEFAULT_VULN_FILTER)

    log.info("API URL :", api_url)

    pb = zafran.proto_file

    if api_key == "" or api_secret == "":
        log.error("Missing api_key/api_secret params")
        return None

    bearer = get_bearer_token(api_url, api_key, api_secret)
    if bearer == "":
        return None

    # Instances
    log.info("Fetching instances/devices...")
    raw_instances = fetch_instances(api_url, bearer)
    log.info("Instances fetched:", len(raw_instances))

    instances_for_flush = []
    instance_meta_by_id = {}

    collected = 0
    i = 0
    n = len(raw_instances)
    while i < n:
        inst = parse_to_instance(raw_instances[i], pb)
        if inst != None:
            zafran.collect_instance(inst)
            instances_for_flush.append(inst)
            collected = collected + 1

            aid = inst.instance_id
            hostname = inst.name
            os_str = inst.operating_system
            ips = inst.asset_information.ip_addresses if inst.asset_information != None else []

            labels = []
            if inst.labels != None:
                j = 0
                while j < len(inst.labels):
                    labels.append(inst.labels[j].label)
                    j = j + 1

            tags = {}
            if inst.key_value_tags != None:
                j = 0
                while j < len(inst.key_value_tags):
                    kv = inst.key_value_tags[j]
                    tags[kv.key] = kv.value
                    j = j + 1

            meta = {"hostname": hostname, "instance_id": aid, "ips": ips, "labels": labels, "os": os_str, "tags": tags}
            instance_meta_by_id[aid] = meta
            export_device_ndjson(meta)

            if collected <= 3:
                log.info("Instance sample:", aid, hostname)

        i = i + 1

    log.info("Instances collected:", collected)

    if collected == 0:
        log.error("No instances collected; aborting vuln fetch to avoid orphan flush scenarios.")
        return None

    # Vulns
    log.info("Fetching vulnerabilities (Spotlight)... filter:", vuln_filter)

    headers = {"Authorization": "Bearer " + bearer, "Accept": "application/json"}

    after = ""
    page = 0
    total_fetched = 0

    vulns_collected = 0
    unmapped = 0
    missing_aid = 0

    while True:
        params = {
            "limit": str(VULNS_LIMIT),
            "filter": vuln_filter,
            "facet": ["cve", "host_info", "remediation"],
        }
        if after != "":
            params["after"] = after

        url = _build_url(api_url, "/spotlight/combined/vulnerabilities/v1", params)
        data = _http_get(url, headers)
        if data == None:
            break

        resources = data.get("resources", [])
        if resources == None:
            resources = []

        page = page + 1
        got = len(resources)
        total_fetched = total_fetched + got
        log.info("Vulns page", page, "got", got, "(total so far", total_fetched, ")")

        if got == 0:
            break

        k = 0
        while k < got:
            raw = resources[k]

            aid = raw.get("aid", "")
            if aid == "":
                host_info = raw.get("host_info", {})
                if host_info != None:
                    aid = host_info.get("aid", "")

            if aid == "":
                missing_aid = missing_aid + 1
                export_unmapped_vuln_ndjson(raw)
                k = k + 1
                continue

            if not (aid in instance_meta_by_id):
                unmapped = unmapped + 1
                export_unmapped_vuln_ndjson(raw)
                k = k + 1
                continue

            v = parse_to_vulnerability(raw, pb)
            if v == None:
                unmapped = unmapped + 1
                export_unmapped_vuln_ndjson(raw)
                k = k + 1
                continue

            zafran.collect_vulnerability(v)
            vulns_collected = vulns_collected + 1

            meta = instance_meta_by_id[aid]
            export_vuln_ndjson({
                "instance_id": aid,
                "hostname": meta.get("hostname", ""),
                "cve": v.cve,
                "severity": _extract_severity(raw),
                "score": _extract_score(raw),
                "status": raw.get("status", ""),
                "first_seen": raw.get("created_timestamp", ""),
                "last_seen": raw.get("updated_timestamp", ""),
                "package": {
                    "name": (v.component.display_name if v.component != None else ""),
                    "version": (v.component.version if v.component != None else ""),
                },
            })

            if (vulns_collected % 1000) == 0:
                log.info("Progress: vulns collected:", vulns_collected, "| unmapped:", unmapped, "| missing_aid:", missing_aid)

            if (vulns_collected % FLUSH_EVERY) == 0:
                _recollect_instances_for_flush(instances_for_flush)
                log.info("Flushing mid-run. Vulns collected so far:", vulns_collected)
                zafran.flush()

            k = k + 1

        meta_obj = data.get("meta", {})
        pag = meta_obj.get("pagination", {}) if meta_obj != None else {}
        nxt = pag.get("after", "") if pag != None else ""

        if nxt == "" or nxt == None:
            break
        after = nxt

    _recollect_instances_for_flush(instances_for_flush)
    log.info("Final flush. Vulns collected:", vulns_collected, "total fetched:", total_fetched)
    zafran.flush()

    log.info("Summary: Vulnerabilities collected:", vulns_collected)
    log.info("Summary: Unmapped vulnerabilities:", unmapped)
    log.info("Summary: Vulnerabilities missing aid:", missing_aid)
    return None

# -------------------------------
# REPL helpers (explicit args)
# -------------------------------

def repl_smoke(api_url, api_key, api_secret):
    """
    REPL helper: verify auth + one lightweight endpoint call.

    Intended usage:
      repl_smoke(api_url=..., api_key=..., api_secret=...)

    Parameters:
      api_url (str): CrowdStrike API URL
      api_key (str): client_id
      api_secret (str): client_secret

    Returns:
      None
    """
    bearer = get_bearer_token(api_url, api_key, api_secret)
    if bearer == "":
        return None
    headers = {"Authorization": "Bearer " + bearer, "Accept": "application/json"}
    url = _build_url(api_url, "/devices/queries/devices-scroll/v1", {"limit": "1"})
    data = _http_get(url, headers)
    if data == None:
        log.error("repl_smoke failed: cannot query devices-scroll")
        return None
    got = len(data.get("resources", []))
    log.info("repl_smoke OK: devices-scroll returned resources:", got)
    return None

def repl_collect_sample(api_url, api_key, api_secret):
    """
    REPL helper: collect a small sample (few instances + limited vulns) so show_collected() is non-empty.

    Behavior:
      - Auth
      - Fetch full device list but only collects first 3 instances
      - Fetch first vuln page and collects up to 50 vulns that map to those instances
      - Emits EXPORT_DEVICE_JSON / EXPORT_VULN_JSON for the collected sample

    Parameters:
      api_url (str): CrowdStrike API URL
      api_key (str): client_id
      api_secret (str): client_secret

    Returns:
      None
    """
    pb = zafran.proto_file
    bearer = get_bearer_token(api_url, api_key, api_secret)
    if bearer == "":
        return None

    raw_instances = fetch_instances(api_url, bearer)
    log.info("repl_collect_sample: instances fetched:", len(raw_instances))

    take = 3
    collected = 0
    instance_meta_by_id = {}

    i = 0
    while i < len(raw_instances) and collected < take:
        inst = parse_to_instance(raw_instances[i], pb)
        if inst != None:
            zafran.collect_instance(inst)
            collected = collected + 1
            aid = inst.instance_id
            meta = {
                "hostname": inst.name,
                "instance_id": aid,
                "ips": (inst.asset_information.ip_addresses if inst.asset_information != None else []),
                "labels": ([inst.labels[0].label] if inst.labels != None and len(inst.labels) > 0 else []),
                "os": inst.operating_system,
                "tags": {},
            }
            instance_meta_by_id[aid] = meta
            export_device_ndjson(meta)
        i = i + 1

    log.info("repl_collect_sample: instances collected:", collected)

    headers = {"Authorization": "Bearer " + bearer, "Accept": "application/json"}
    url = _build_url(api_url, "/spotlight/combined/vulnerabilities/v1", {
        "limit": str(VULNS_LIMIT),
        "filter": DEFAULT_VULN_FILTER,
        "facet": ["cve", "host_info", "remediation"],
    })
    data = _http_get(url, headers)
    if data == None:
        log.error("repl_collect_sample: vuln first page fetch failed")
        return None

    resources = data.get("resources", [])
    if resources == None:
        resources = []
    log.info("repl_collect_sample: vulns first page got:", len(resources))

    vtake = 50
    vcol = 0
    k = 0
    while k < len(resources) and vcol < vtake:
        raw = resources[k]
        aid = raw.get("aid", "")
        if aid == "":
            host_info = raw.get("host_info", {})
            if host_info != None:
                aid = host_info.get("aid", "")

        if aid != "" and (aid in instance_meta_by_id):
            v = parse_to_vulnerability(raw, pb)
            if v != None:
                zafran.collect_vulnerability(v)
                export_vuln_ndjson({
                    "instance_id": aid,
                    "hostname": instance_meta_by_id[aid].get("hostname", ""),
                    "cve": v.cve,
                    "severity": _extract_severity(raw),
                    "score": _extract_score(raw),
                })
                vcol = vcol + 1
        k = k + 1

    log.info("repl_collect_sample: vulns collected:", vcol)
    return None

# -------------------------------
# REPL wrappers (do NOT reference global `params`)
#   Call them like: repl_collect_sample_from_params(**params)
# -------------------------------

def repl_smoke_from_params(**kwargs):
    """
    REPL wrapper: same as repl_smoke(), but accepts a params-dict expanded via **params.

    Intended usage:
      repl_smoke_from_params(**params)

    Parameters (kwargs):
      api_url (str)
      api_key (str)
      api_secret (str)

    Returns:
      None
    """
    return repl_smoke(
        api_url=kwargs.get("api_url", ""),
        api_key=kwargs.get("api_key", ""),
        api_secret=kwargs.get("api_secret", ""),
    )

def repl_collect_sample_from_params(**kwargs):
    """
    REPL wrapper: same as repl_collect_sample(), but accepts a params-dict expanded via **params.

    Intended usage:
      repl_collect_sample_from_params(**params)

    Parameters (kwargs):
      api_url (str)
      api_key (str)
      api_secret (str)

    Returns:
      None
    """
    return repl_collect_sample(
        api_url=kwargs.get("api_url", ""),
        api_key=kwargs.get("api_key", ""),
        api_secret=kwargs.get("api_secret", ""),
    )

def repl_run_full_from_params(**kwargs):
    """
    REPL wrapper: run the full integration flow in REPL.

    Intended usage:
      repl_run_full_from_params(**params)

    Parameters (kwargs):
      same as main(**kwargs)

    Returns:
      None
    """
    return main(**kwargs)
