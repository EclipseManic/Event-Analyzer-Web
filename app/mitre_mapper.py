"""MITRE ATT&CK mapping for Event-Analyzer."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

_mitre_cache: dict = {}

EVENT_TO_MITRE: Dict[str, List[Dict[str, str]]] = {
    "process_created": [
        {"id": "T1059", "name": "Command and Scripting Interpreter"},
        {"id": "T1204", "name": "User Execution"},
    ],
    "network_connection": [
        {"id": "T1071", "name": "Application Layer Protocol"},
    ],
    "file_created": [
        {"id": "T1105", "name": "Ingress Tool Transfer"},
    ],
    "registry_value_set": [
        {"id": "T1112", "name": "Modify Registry"},
    ],
    "service_installed": [
        {"id": "T1543.003", "name": "Windows Service"},
    ],
    "dns_query": [
        {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"},
    ],
    "powershell_scriptblock": [
        {"id": "T1059.001", "name": "PowerShell"},
    ],
    "account_created": [
        {"id": "T1136.001", "name": "Local Account"},
    ],
    "account_disabled": [
        {"id": "T1531", "name": "Account Manipulation"},
    ],
    "account_deleted": [
        {"id": "T1531", "name": "Account Manipulation"},
    ],
    "logon": [
        {"id": "T1078", "name": "Valid Accounts"},
    ],
    "logon_failed": [
        {"id": "T1110", "name": "Brute Force"},
    ],
    "explicit_logon": [
        {"id": "T1078", "name": "Valid Accounts"},
    ],
}


def map_event(event: Dict[str, Any]) -> List[Dict[str, str]]:
    category = event.get("event_category", "")
    event_id = event.get("event_id")
    key = (category, event_id)
    if key in _mitre_cache:
        return _mitre_cache[key]
    techniques = EVENT_TO_MITRE.get(category, [])
    if not techniques:
        if event_id == 4648:
            techniques = [{"id": "T1078", "name": "Valid Accounts"}]
        elif event_id == 4672:
            techniques = [{"id": "T1068", "name": "Exploitation for Privilege Escalation"}]
        elif event_id in (4728, 4732, 4756):
            techniques = [{"id": "T1098", "name": "Account Manipulation"}]
        elif event_id == 4698:
            techniques = [{"id": "T1053.005", "name": "Scheduled Task"}]
        elif event_id == 7045:
            techniques = [{"id": "T1543.003", "name": "Windows Service"}]
    _mitre_cache[key] = techniques
    return techniques


def get_event_ids_for_technique(technique_id: str) -> List[int]:
    mapping = {
        "T1059": [4688, 1],
        "T1059.001": [4104, 400, 403, 800],
        "T1204": [4688, 1],
        "T1071": [3],
        "T1105": [11],
        "T1112": [13],
        "T1543.003": [7045, 4697],
        "T1048": [22],
        "T1136.001": [4720],
        "T1531": [4725, 4726],
        "T1078": [4624, 4648],
        "T1110": [4625],
        "T1068": [4672],
        "T1098": [4728, 4732, 4756],
        "T1053.005": [4698],
    }
    return mapping.get(technique_id, [])
