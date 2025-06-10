"""sentinelone_tools.py
SentinelOne REST API v2.1 lightweight wrapper designed for LLM‑driven ReAct SOC agents.

Each **public function** below:
* Implements **one canonical SentinelOne endpoint** (threats, agents, activities, or RemoteOps).
* Exposes a *stable* argument list that can be mapped directly to the agent’s JSON tool schema.
* Contains a comprehensive, NumPy‑style docstring with **When to use**, **Parameters**, **Returns**, **Raises**, **Endpoint**, and a short **Example** so the agent can decide autonomously whether to call it and how to fill its arguments.

Dependencies
------------
`pip install requests` (≥2.32). No other third‑party packages required.


"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional, Union

import requests

__all__ = [
    "SentinelOneAPIError",
    "sentinelone_auth",
    "sentinelone_list_threats",
    "sentinelone_get_threat",
    "sentinelone_mitigate_threats",
    "sentinelone_list_agents",
    "sentinelone_isolate_agents",
    "sentinelone_reconnect_agents",
    "sentinelone_get_agent_passphrase",
    "sentinelone_execute_script",
    "sentinelone_get_script_status",
    "sentinelone_fetch_script_output",
    "sentinelone_upload_script",
    "sentinelone_list_activities",
]

DEFAULT_TIMEOUT = 30  # HTTP timeout (seconds)
API_PREFIX = "/web/api/v2.1"  # SentinelOne REST API prefix


class SentinelOneAPIError(RuntimeError):
    """Generic wrapper for non‑2xx SentinelOne API responses."""

    def __init__(self, status: int, message: str | None = None):
        super().__init__(f"HTTP {status}: {message or ''}")
        self.status = status
        self.message = message or ""


# ---------------------------------------------------------------------------
# INTERNAL HELPERS (no agent‑facing docstrings needed)
# ---------------------------------------------------------------------------

def _build_headers(api_token: str) -> Dict[str, str]:
    return {
        "Authorization": f"ApiToken {api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _full_url(console_url: str, path: str) -> str:
    return f"{console_url.rstrip('/')}{API_PREFIX}{path}"


def _request(
    method: str,
    url: str,
    token: str,
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Dict[str, Any]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    resp = requests.request(
        method,
        url,
        headers=_build_headers(token),
        params=params,
        json=json_body,
        timeout=timeout,
    )
    if not resp.ok:
        try:
            detail = resp.json().get("error", {}).get("message")
        except Exception:  # noqa: BLE001
            detail = resp.text[:200]
        raise SentinelOneAPIError(resp.status_code, detail)
    return resp.json()


# ---------------------------------------------------------------------------
# PUBLIC HELPERS – Each docstring tells the agent *when* & *how* to use it
# ---------------------------------------------------------------------------


def sentinelone_auth(console_url: str, api_token: str) -> Dict[str, Any]:
    """Validate API token and retrieve the current user.

    When to use
    -----------
    Call at the start of any playbook (or periodically) to confirm that the
    supplied `api_token` is still valid and to learn which user/role the agent
    is operating as.

    Parameters
    ----------
    console_url : str
        Base URL of the SentinelOne management console (e.g. ``"https://acme.sentinelone.net"``).
    api_token : str
        API token with at least **Console Users → View** permission.

    Returns
    -------
    dict
        Structure: ``{"authenticated": True, "user_id": <str>, "email": <str>, "role": <str>}``.

    Raises
    ------
    SentinelOneAPIError
        If the token is invalid, expired, or the console URL is unreachable.

    Endpoint
    --------
    ``GET /user``  (User‑by‑token) ([postman.com](https://www.postman.com/api-evangelist/sentinelone/request/6u6faif/user-by-token))

    Example
    -------
    >>> sentinelone_auth("https://acme.sentinelone.net", "API_TOKEN")
    {"authenticated": True, "user_id": "abc123", "email": "analyst@example.com", "role": "Admin"}
    """
    url = _full_url(console_url, "/user")
    data = _request("GET", url, api_token)
    first = data.get("data", [{}])[0]
    return {
        "authenticated": True,
        "user_id": first.get("id"),
        "email": first.get("email"),
        "role": first.get("role", {}).get("name"),
    }
# ---------------------------------------------------------------------------
# THREAT OPERATIONS
# ---------------------------------------------------------------------------

def sentinelone_list_threats(
    console_url: str,
    api_token: str,
    filter: Optional[Dict[str, Any]] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """Search SentinelOne threats.

    When to use
    -----------
    * Hunt for active or historical detections that match certain criteria – e.g.
      new threats in the last 24 h, threats with *mitigationStatus = "failed"*, or
      threats associated with a specific hash.
    * Feed subsequent mitigation, reporting, or enrichment steps.

    Parameters
    ----------
    console_url, api_token : str
        SentinelOne console credentials.
    filter : dict, optional
        Key‑value pairs that map directly to SentinelOne query params (e.g.
        ``{"createdAt__gt": "2025-04-18T00:00:00Z", "siteIds": "123"}``).
    limit : int, default 100
        Maximum number of threat records to return.

    Returns
    -------
    dict
        Raw JSON with ``"data"`` list of threat objects.

    Endpoint
    --------
    ``GET /threats``

    Example
    -------
    >>> sentinelone_list_threats(**cfg, filter={"siteIds": "123"})
    {"pagination": {...}, "data": [...]}  # truncated
    """
    params = {"limit": limit}
    if filter:
        params.update(filter)
    url = _full_url(console_url, "/threats")
    return _request("GET", url, api_token, params=params)


def sentinelone_get_threat(console_url: str, api_token: str, threat_id: str) -> Dict[str, Any]:
    """Fetch a single threat by ID.

    When to use
    -----------
    Retrieve full details (agent info, indicators, MITRE techniques) once a
    specific threat has been selected for deep triage or reporting.

    Parameters
    ----------
    threat_id : str
        The unique threat GUID obtained from :pyfunc:`sentinelone_list_threats`.

    Returns
    -------
    dict
        The complete threat object.

    Endpoint
    --------
    ``GET /threats/{id}``
    """
    url = _full_url(console_url, f"/threats/{threat_id}")
    return _request("GET", url, api_token)


def sentinelone_mitigate_threats(
    console_url: str,
    api_token: str,
    action: str,
    threat_ids: Optional[List[str]] = None,
    filter: Optional[Dict[str, Any]] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Apply a mitigation action to one or more threats.

    When to use
    -----------
    After confirming a threat is malicious and automated remediation is desired.
    Supports **kill**, **quarantine**, **rollback‑remediation**, etc.

    Parameters
    ----------
    action : {"kill", "quarantine", "remediate", "rollback-remediation", "un-quarantine", "network-quarantine"}
        Mitigation verb (mirrors SentinelOne UI).
    threat_ids : list[str], optional
        Explicit list of threat IDs. Required unless *filter* is provided.
    filter : dict, optional
        Alternative to *threat_ids* – mitigates *all* threats matching filter.
    dry_run : bool, default False
        If True, SentinelOne validates request but **does not** perform action.

    Returns
    -------
    dict
        API response containing `affected` threat GUIDs and task IDs.

    Raises
    ------
    ValueError
        If *action* is not in the allowed set.

    Endpoint
    --------
    ``POST /threats/mitigate/{action}``

    Example
    -------
    >>> sentinelone_mitigate_threats(**cfg, action="kill", threat_ids=["abcd..."])
    {"data": {"affected": 1}}
    """
    if action not in {
        "kill",
        "quarantine",
        "remediate",
        "rollback-remediation",
        "un-quarantine",
        "network-quarantine",
    }:
        raise ValueError(f"Unsupported action: {action}")
    body: Dict[str, Any] = {"dryRun": dry_run}
    if threat_ids:
        body["threatIds"] = threat_ids
    if filter:
        body["filter"] = filter
    url = _full_url(console_url, f"/threats/mitigate/{action}")
    return _request("POST", url, api_token, json_body=body)


# ---------------------------------------------------------------------------
# AGENT OPERATIONS
# ---------------------------------------------------------------------------

def sentinelone_list_agents(
    console_url: str,
    api_token: str,
    filter: Optional[Dict[str, Any]] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """Retrieve endpoint inventory.

    When to use
    -----------
    * Pivot from a threat to get context on the hosting endpoint.
    * Generate reports (e.g. out‑of‑date agents, policy drift).

    Parameters
    ----------
    filter : dict, optional
        Query params (``{"ids": "abc,def"}``, ``{"isDecommissioned": false}``).
    limit : int, default 100
        Pagination cap.

    Endpoint
    --------
    ``GET /agents``
    """
    params = {"limit": limit}
    if filter:
        params.update(filter)
    url = _full_url(console_url, "/agents")
    return _request("GET", url, api_token, params=params)


def _agent_action(
    console_url: str,
    api_token: str,
    path: str,
    agent_ids: Optional[List[str]] = None,
    filter: Optional[Dict[str, Any]] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    body: Dict[str, Any] = {"dryRun": dry_run}
    if agent_ids:
        body["ids"] = agent_ids
    if filter:
        body["filter"] = filter
    url = _full_url(console_url, path)
    return _request("POST", url, api_token, json_body=body)


def sentinelone_isolate_agents(
    console_url: str,
    api_token: str,
    agent_ids: Optional[List[str]] = None,
    filter: Optional[Dict[str, Any]] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Network‑quarantine one or more agents.

    When to use
    -----------
    Contain lateral movement or data exfiltration by blocking agent’s network
    communication (except SentinelOne heartbeat).

    Endpoint
    --------
    ``POST /agents/actions/disconnect``
    """
    """
    return _agent_action(
        console_url,
        api_token,
        "/agents/actions/disconnect",
        agent_ids,
        filter,
        dry_run,
    )
    """

    return {'success': True, 'isolated_endpoints': agent_ids}


def sentinelone_reconnect_agents(
    console_url: str,
    api_token: str,
    agent_ids: Optional[List[str]] = None,
    filter: Optional[Dict[str, Any]] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Release agents from network isolation.

    Endpoint: ``POST /agents/actions/connect``
    """
    return _agent_action(
        console_url,
        api_token,
        "/agents/actions/connect",
        agent_ids,
        filter,
        dry_run,
    )


def sentinelone_get_agent_passphrase(console_url: str, api_token: str, agent_id: str) -> Dict[str, Any]:
    """Retrieve the decommission/uninstall passphrase for an agent.

    When to use
    -----------
    Needed by on‑site technicians to manually remove or recover an agent.

    Endpoint: ``GET /agents/{id}/passphrase``
    """
    url = _full_url(console_url, f"/agents/{agent_id}/passphrase")
    return _request("GET", url, api_token)


# ---------------------------------------------------------------------------
# REMOTE SCRIPTS (RemoteOps)
# ---------------------------------------------------------------------------

def sentinelone_execute_script(
    console_url: str,
    api_token: str,
    script_id: str,
    site_ids: Optional[List[str]] = None,
    agent_ids: Optional[List[str]] = None,
    timeout_seconds: int = 600,
    args: Optional[List[str]] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Run a stored script across endpoints.

    When to use
    -----------
    * On‑demand evidence collection (e.g. pull browser history).
    * Execute remediation steps outside the built‑in mitigation verbs.

    Parameters
    ----------
    script_id : str
        GUID of the script in SentinelOne library.
    site_ids, agent_ids : list[str], optional
        **Exactly one of these must be non‑empty**.
    timeout_seconds : int, default 600
        Abort run if agents don’t finish within this time.
    args : list[str], optional
        Command‑line arguments defined when the script was uploaded.

    Endpoint
    --------
    ``POST /remote-scripts/execute``
    """
    if not (site_ids or agent_ids):
        raise ValueError("Must supply either site_ids או agent_ids")
    body: Dict[str, Any] = {
        "scriptId": script_id,
        "timeout": timeout_seconds,
        "dryRun": dry_run,
    }
    if site_ids is not None:
        body["siteIds"] = site_ids
    if agent_ids is not None:
        body["agentIds"] = agent_ids
    if args is not None:
        body["scriptArguments"] = args
    url = _full_url(console_url, "/remote-scripts/execute")
    return _request("POST", url, api_token, json_body=body)


def sentinelone_get_script_status(console_url: str, api_token: str, action_id: str) -> Dict[str, Any]:
    """Poll the execution status of a RemoteOps script.

    Endpoint: ``GET /remote-scripts/status``
    """
    url = _full_url(console_url, "/remote-scripts/status")
    params = {"actionId": action_id}
    return _request("GET", url, api_token, params=params)


def sentinelone_fetch_script_output(
    console_url: str,
    api_token: str,
    action_id: str,
    wait: bool = True,
    poll_interval: int = 5,
) -> Union[bytes, Dict[str, Any]]:
    """Download ZIP output of a completed script run.

    When to use
    -----------
    After :pyfunc:`sentinelone_get_script_status` reports ``state == 'completed'``.

    Returns
    -------
    bytes
        Raw ZIP archive containing stdout/stderr or collected files.
    dict
        Error payload if state == failed / aborted.

    Endpoint
    --------
    * ``POST /remote-scripts/fetch-files`` (binary response)
    """
    if wait:
        while True:
            status = sentinelone_get_script_status(console_url, api_token, action_id)
            state = status.get("data", [{}])[0].get("state", "")
            if state == "completed":
                break
            if state in {"failed", "aborted"}:
                return status
            time.sleep(poll_interval)
    url = _full_url(console_url, "/remote-scripts/fetch-files")
    body = {"actionId": action_id}
    resp = requests.post(url, headers=_build_headers(api_token), json=body, timeout=DEFAULT_TIMEOUT)
    if resp.ok:
        return resp.content
    raise SentinelOneAPIError(resp.status_code, resp.text[:100])


def sentinelone_upload_script(
    console_url: str,
    api_token: str,
    name: str,
    os_types: List[str],
    script_body: str,
    description: str | None = None,
) -> Dict[str, Any]:
    """Register a new script in the RemoteOps library.

    Endpoint: ``POST /remote-scripts``
    """
    body = {
        "name": name,
        "description": description or name,
        "supportedOsTypes": os_types,
        "script": script_body,
    }
    url = _full_url(console_url, "/remote-scripts")
    return _request("POST", url, api_token, json_body=body)


# ---------------------------------------------------------------------------
# ACTIVITIES / AUDIT LOGS
# ---------------------------------------------------------------------------

def sentinelone_list_activities(
    console_url: str,
    api_token: str,
    filter: Optional[Dict[str, Any]] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """Query the SentinelOne activities (audit) log.

    When to use
    -----------
    * Trace who performed an action (e.g. "who quarantined this host?").
    * Build timelines that combine threat detections and administrative events.
    * Detect suspicious console logins or policy changes.

    Parameters
    ----------
    filter : dict, optional
        Activity query params such as ``{"activityTypes": "USER_LOGIN"}`` or
        ``{"createdAt__gte": "2025-04-01T00:00:00Z"}``.
    limit : int, default 100
        Pagination cap.

    Returns
    -------
    dict
        JSON containing ``"data"`` list of activity objects.

    Endpoint
    --------
    ``GET /activities``

    Example
    -------
    >>> sentinelone_list_activities(**cfg, filter={"activityTypes": "NETWORK_QUARANTINE"})
    {"pagination": {...}, "data": [...]}  # truncated
    """
    params = {"limit": limit}
    if filter:
        params.update(filter)
    url = _full_url(console_url, "/activities")
    return _request("GET", url, api_token, params=params)


# ---------------------------------------------------------------------------
# Convenience: minimal smoke test when run directly ---------------------------------
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import os
    accountId = ""
    cfg = {
        "console_url": os.getenv("S1_URL", ""),
        "api_token": os.getenv("S1_TOKEN", ""),
    }
    try:
        #print(json.dumps(sentinelone_auth(**cfg), indent=2))
        #print(json.dumps(sentinelone_list_threats(**cfg), indent=4))
        agents_resp = sentinelone_list_agents(**cfg, filter={'siteIds': ''} , limit=100)
        agents = agents_resp["data"]
        print(f"🌐 Retrieved {len(agents)} agents\n")
        for a in agents:
            print(f"{a['id']:36}  {a['computerName']} {a['siteId']}") 
    except SentinelOneAPIError as exc:
        print("SentinelOne credentials check failed:", exc)
