"""
SentinelOne Mock SOC Tools – **Stateless LLM Edition**
=====================================================

A fully‑self‑contained mock of the most common SentinelOne Management API
workflows.  **Every public function is *stateless*: it accepts an
`api_token` and `base_url` directly**, so an LLM can invoke tools without
needing to preserve a session handle.

Each function begins with a **Tool Description** block that tells the agent
**when** it should call the tool, **how** to format inputs, and what the
return object looks like.  Standard *NumPy‑style* sections follow for extra
clarity.

Design principles
-----------------
* Mirrors the real `/web/api/v2.1` schema where helpful (e.g. threat fields).
* Fixed random seed for deterministic IDs → repeatable unit tests.
* All timestamps are ISO‑8601 UTC strings.
* Functions finish synchronously for simplicity in mock land.
"""
from __future__ import annotations
import random
import string
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

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

# ---------------------------------------------------------------------------
# Mock data and helpers
# ---------------------------------------------------------------------------

_random = random.Random(42)

def _rand_id(prefix: str = "") -> str:
    return prefix + "".join(_random.choices(string.ascii_lowercase + string.digits, k=12))

_NOW = datetime.now(timezone.utc)
_MOCK_SESSION_STORE: Dict[str, Dict[str, Any]] = {}

_MOCK_AGENTS: List[Dict[str, Any]] = [
    {
        "id": _rand_id("agt-"),
        "siteId": "site-01",
        "computerName": "DESKTOP-A12",
        "ipAddresses": ["10.0.5.15"],
        "osName": "Windows 11",
        "networkStatus": "connected",
        "operationalState": "active",
        "lastSeen": (_NOW - timedelta(minutes=3)).isoformat(),
    },
    {
        "id": _rand_id("agt-"),
        "siteId": "site-02",
        "computerName": "SRV-WEB-01",
        "ipAddresses": ["192.168.10.21"],
        "osName": "Windows Server 2022",
        "networkStatus": "connected",
        "operationalState": "active",
        "lastSeen": (_NOW - timedelta(minutes=8)).isoformat(),
    },
]

_MOCK_THREATS: List[Dict[str, Any]] = [
    {
        "id": _rand_id("thr-"),
        "agentId": _MOCK_AGENTS[0]["id"],
        "malicious": True,
        "classification": "malware",
        "mitigationStatus": "active",
        "filePath": "C:\\Users\\Public\\dropper.exe",
        "sha1": "23ad2b9c49dc6ffa4ce8e876a1d492aa1d6d1234",
        "createdAt": (_NOW - timedelta(hours=2)).isoformat(),
        "updatedAt": (_NOW - timedelta(hours=2)).isoformat(),
    },
    {
        "id": _rand_id("thr-"),
        "agentId": _MOCK_AGENTS[1]["id"],
        "malicious": True,
        "classification": "malware",
        "mitigationStatus": "mitigated",
        "filePath": "C:\\Temp\\cryptominer.exe",
        "sha1": "94fae843d458eade982f4bd5d7a3cc1e23e0beef",
        "createdAt": (_NOW - timedelta(days=1)).isoformat(),
        "updatedAt": (_NOW - timedelta(hours=22)).isoformat(),
    },
]

_MOCK_SCRIPTS: Dict[str, Dict[str, Any]] = {}
_MOCK_ACTIVITIES: List[Dict[str, Any]] = []

# ---------------------------------------------------------------------------
# Auth helpers (mock)
# ---------------------------------------------------------------------------

class SentinelOneAPIError(RuntimeError):
    """Raised when authentication or request validation fails."""


def sentinelone_auth(api_token: str, base_url: str) -> Dict[str, Any]:
    """Minimal token validation used internally by every public helper."""
    if not api_token or len(api_token) < 10:
        raise SentinelOneAPIError("HTTP 401 Unauthorized – bad token")
    sid = _rand_id("sess-")
    _MOCK_SESSION_STORE[sid] = {"token": api_token, "base_url": base_url.rstrip("/"), "created_at": time.time()}
    return {"session_id": sid, "base_url": base_url.rstrip("/")}


def _ensure_auth(api_token: str, base_url: str):
    """Helper so tools appear to *log in* without exposing sessions."""
    return sentinelone_auth(api_token, base_url)

# ---------------------------------------------------------------------------
# Public stateless tools (detailed docstrings)
# ---------------------------------------------------------------------------

def sentinelone_list_threats(api_token: str, base_url: str, *, site_id: str | None = None, limit: int = 20) -> List[Dict[str, Any]]:
    """List current threats.

    Tool Description
    ----------------
    **When to call:** Kick‑off of any malware playbook to enumerate threats.
    **How to call:** Provide ``api_token``, ``base_url``; optional
    ``site_id`` and ``limit``.
    """
    _ensure_auth(api_token, base_url)
    threats = _MOCK_THREATS if site_id is None else [t for t in _MOCK_THREATS if any(a["id"] == t["agentId"] and a["siteId"] == site_id for a in _MOCK_AGENTS)]
    return sorted(threats, key=lambda x: x["createdAt"], reverse=True)[:limit]


def sentinelone_get_threat(api_token: str, base_url: str, threat_id: str) -> Dict[str, Any]:
    """Return full threat details for *threat_id*."""
    _ensure_auth(api_token, base_url)
    for t in _MOCK_THREATS:
        if t["id"] == threat_id:
            return t
    raise SentinelOneAPIError("Threat not found")


def sentinelone_mitigate_threats(api_token: str, base_url: str, threat_ids: List[str], *, action: str = "kill") -> Dict[str, Any]:
    """Perform ``action`` (kill | quarantine | rollback) on threats."""
    _ensure_auth(api_token, base_url)
    succ, fail = [], []
    for tid in threat_ids:
        th = next((t for t in _MOCK_THREATS if t["id"] == tid), None)
        if th:
            th["mitigationStatus"] = "mitigated"
            th["updatedAt"] = datetime.now(timezone.utc).isoformat()
            succ.append(tid)
        else:
            fail.append({"id": tid, "error": "NotFound"})
    return {"action": action, "succeeded": succ, "failed": fail}


def sentinelone_list_agents(api_token: str, base_url: str, *, site_id: str | None = None) -> List[Dict[str, Any]]:
    """Enumerate agents; filter by *site_id* if supplied."""
    _ensure_auth(api_token, base_url)
    return _MOCK_AGENTS if site_id is None else [a for a in _MOCK_AGENTS if a["siteId"] == site_id]


def sentinelone_isolate_agents(api_token: str, base_url: str, agent_ids: List[str]) -> Dict[str, Any]:
    """Set ``networkStatus`` → ``isolated`` for each agent in *agent_ids*."""
    _ensure_auth(api_token, base_url)
    res = {"succeeded": [], "failed": []}
    for aid in agent_ids:
        ag = next((a for a in _MOCK_AGENTS if a["id"] == aid), None)
        if ag:
            ag["networkStatus"] = "isolated"
            res["succeeded"].append(aid)
        else:
            res["failed"].append({"id": aid, "error": "NotFound"})
    return res


def sentinelone_reconnect_agents(api_token: str, base_url: str, agent_ids: List[str]) -> Dict[str, Any]:
    """Reverse isolation (``networkStatus`` → ``connected``)."""
    _ensure_auth(api_token, base_url)
    res = {"succeeded": [], "failed": []}
    for aid in agent_ids:
        ag = next((a for a in _MOCK_AGENTS if a["id"] == aid), None)
        if ag:
            ag["networkStatus"] = "connected"
            res["succeeded"].append(aid)
        else:
            res["failed"].append({"id": aid, "error": "NotFound"})
    return res


def sentinelone_get_agent_passphrase(api_token: str, base_url: str, agent_id: str) -> str:
    """Return a 16‑character uninstall passphrase for *agent_id*."""
    _ensure_auth(api_token, base_url)
    if not any(a["id"] == agent_id for a in _MOCK_AGENTS):
        raise SentinelOneAPIError("Agent not found")
    return _rand_id()[:16]


def sentinelone_execute_script(api_token: str, base_url: str, agent_ids: List[str], script_name: str, script_content: str) -> str:
    """Run RemoteOps script; returns ``job_id``."""
    _ensure_auth(api_token, base_url)
    jid = _rand_id("job-")
    _MOCK_SCRIPTS[jid] = {"agents": agent_ids, "name": script_name, "content": script_content, "status": "completed", "createdAt": datetime.now(timezone.utc).isoformat(), "output": f"Script '{script_name}' finished successfully"}
    return jid


def sentinelone_get_script_status(api_token: str, base_url: str, job_id: str) -> str:
    """Return status (queued|running|completed) for *job_id*."""
    _ensure_auth(api_token, base_url)
    job = _MOCK_SCRIPTS.get(job_id)
    if not job:
        raise SentinelOneAPIError("Job not found")
    return job["status"]


def sentinelone_fetch_script_output(api_token: str, base_url: str, job_id: str) -> str:
    """Return stdout/stderr of completed *job_id*."""
    _ensure_auth(api_token, base_url)
    job = _MOCK_SCRIPTS.get(job_id)
    if not job or job["status"] != "completed":
        raise SentinelOneAPIError("Output not available")
    return job["output"]


def sentinelone_upload_script(api_token: str, base_url: str, script_name: str, script_path: str) -> str:
    """Upload re‑usable script; returns ``script_id``."""
    _ensure_auth(api_token, base_url)
    sid = _rand_id("scr-")
    _MOCK_SCRIPTS[sid] = {"name": script_name, "path": script_path, "uploadedAt": datetime.now(timezone.utc).isoformat()}
    return sid


def sentinelone_list_activities(api_token: str, base_url: str, *, since_hours: int = 1) -> List[Dict[str, Any]]:
    """List recent console activities within *since_hours* look‑back.

    Tool Description
    ----------------
    **When to call:** To enrich incident timelines with console actions or
    to verify that expected mitigation events took place.

    **How to call:** Provide the usual ``api_token``, ``base_url`` and an
    optional integer ``since_hours`` (default 1).
    """
    _ensure_auth(api_token, base_url)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    return [a for a in _MOCK_ACTIVITIES if datetime.fromisoformat(a["createdAt"]) >= cutoff]

# ---------------------------------------------------------------------------
# Self‑test – exercise **every** public function
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    token = "demo_token_123456"
    url = "https://demo.sentinelone.test"

    # 1) Agents
    all_agents = sentinelone_list_agents(token, url)
    print("Agents:", all_agents)

    # 2) Threats
    threats = sentinelone_list_threats(token, url)
    print("Threats:", threats)

    if threats:
        th_id = threats[0]["id"]
        print("Threat details:", sentinelone_get_threat(token, url, th_id))
        print("Mitigate:", sentinelone_mitigate_threats(token, url, [th_id], action="kill"))

    # 3) Isolation cycle
    first_agent = all_agents[0]["id"]
    print("Isolate:", sentinelone_isolate_agents(token, url, [first_agent]))
    print("Reconnect:", sentinelone_reconnect_agents(token, url, [first_agent]))

    # 4) Passphrase retrieval
    print("Offline passphrase:", sentinelone_get_agent_passphrase(token, url, first_agent))

    # 5) RemoteOps full flow
    job = sentinelone_execute_script(token, url, [first_agent], "whoami", "whoami")
    print("Job status:", sentinelone_get_script_status(token, url, job))
    print("Job output:", sentinelone_fetch_script_output(token, url, job))

    # 6) Script upload
    scr_id = sentinelone_upload_script(token, url, "cleanup_temp", "/scripts/cleanup.ps1")
    print("Script uploaded:", scr_id)

    # 7) Activities feed (expected empty)
    print("Activities:", sentinelone_list_activities(token, url, since_hours=24))
