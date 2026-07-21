"""Sigma rule matching for Event-Analyzer."""

from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.logger import get_logger

logger = get_logger("sigma_matcher")

_rules_cache: Optional[List[Dict[str, Any]]] = None
_compiled_rules: Optional[List[Dict[str, Any]]] = None
_cache_lock = threading.Lock()

_RULES_PATH = Path(__file__).resolve().parent.parent / "data" / "sigma" / "sigma_rules.json"

_MITRE_MAP = {
    "attack.t1059.001": "PowerShell",
    "attack.t1204": "User Execution",
    "attack.t1547.001": "Registry Run Keys / Startup Folder",
    "attack.t1071": "Application Layer Protocol",
    "attack.t1569.002": "Service Execution",
    "attack.t1047": "Windows Management Instrumentation",
    "attack.t1543.003": "Windows Service",
    "attack.t1003": "OS Credential Dumping",
    "attack.t1003.001": "LSASS Memory",
    "attack.t1003.002": "Security Account Manager",
    "attack.t1003.004": "LSA Secrets",
    "attack.t1003.005": "Cached Domain Credentials",
    "attack.t1003.006": "DCSync",
    "attack.t1021": "Remote Services",
    "attack.t1021.001": "Remote Desktop",
    "attack.t1021.002": "SMB/Windows Admin Shares",
    "attack.t1021.003": "Distributed Component Object Model",
    "attack.t1021.004": "SSH",
    "attack.t1021.005": "VNC",
    "attack.t1021.006": "Windows Remote Management",
    "attack.t1053": "Scheduled Task",
    "attack.t1053.002": "At",
    "attack.t1053.005": "Scheduled Task",
    "attack.t1018": "Remote System Discovery",
    "attack.t1082": "System Information Discovery",
    "attack.t1083": "File and Directory Discovery",
    "attack.t1087": "Account Discovery",
    "attack.t1482": "Domain Trust Discovery",
    "attack.t1069": "Permission Groups Discovery",
    "attack.t1518": "Software Discovery",
    "attack.t1552": "Unsecured Credentials",
    "attack.t1555": "Credentials from Password Stores",
    "attack.t1555.003": "Web Browsers",
    "attack.t1078": "Valid Accounts",
    "attack.t1078.002": "Domain Accounts",
    "attack.t1078.003": "Local Accounts",
    "attack.t1098": "Account Manipulation",
    "attack.t1136": "Create Account",
    "attack.t1136.001": "Local Account",
    "attack.t1136.002": "Domain Account",
    "attack.t1222": "File and Directory Permissions Modification",
    "attack.t1222.001": "Windows File and Directory Permissions Modification",
    "attack.t1565": "Data Manipulation",
    "attack.t1574": "Hijack Execution Flow",
    "attack.t1574.001": "DLL Search Order Hijacking",
    "attack.t1574.002": "DLL Side-Loading",
    "attack.t1574.011": "Services File Permissions Weakness",
    "attack.t1055": "Process Injection",
    "attack.t1055.001": "Dynamic-link Library Injection",
    "attack.t1055.012": "Process Hollowing",
    "attack.t1505": "Server Software Component",
    "attack.t1505.002": "Transport Agent",
}


def _field_with_prefix(field: str, field_prefix: str) -> str:
    if field_prefix and not field.startswith(field_prefix):
        return f"{field_prefix}{field}"
    return field


def _convert_selection_value(value: Any, field: str) -> Optional[Tuple[str, str, Any]]:
    if isinstance(value, str):
        if value.startswith("re:"):
            return ("regex", field, value[3:].strip())
        if value.startswith("contains:"):
            term = value[9:].strip()
            return ("regex", field, re.escape(term))
        if value.startswith("startswith:"):
            term = value[11:].strip()
            return ("regex", field, "^" + re.escape(term))
        if value.startswith("endswith:"):
            term = value[9:].strip()
            return ("regex", field, re.escape(term) + "$")
        if "|" in field:
            field_name, modifier = field.split("|", 1)
            if modifier == "re":
                return ("regex", field_name, value)
            if modifier == "contains":
                return ("regex", field_name, re.escape(value))
            if modifier == "startswith":
                return ("regex", field_name, "^" + re.escape(value))
            if modifier == "endswith":
                return ("regex", field_name, re.escape(value) + "$")
        return ("exact", field, value.lower() if isinstance(value, str) else value)

    if isinstance(value, (int, float)):
        return ("exact", field, value)

    if isinstance(value, list):
        patterns = []
        for item in value:
            result = _convert_selection_value(item, field)
            if result:
                patterns.append(result)
        if patterns:
            return ("or_group", field, patterns)

    return None


def _convert_selection(selection: Dict[str, Any], field_prefix: str) -> List[Dict[str, Any]]:
    conditions = []
    for field, value in selection.items():
        if field.startswith("|"):
            continue
        prefixed_field = _field_with_prefix(field, field_prefix)
        clean_field = prefixed_field.split("|")[0]
        result = _convert_selection_value(value, clean_field)
        if result:
            cond_type, cond_field, cond_pattern = result
            if cond_type == "regex":
                conditions.append({"field": cond_field, "pattern": cond_pattern})
            elif cond_type == "exact":
                if isinstance(cond_pattern, str):
                    conditions.append({"field": cond_field, "pattern": f"^{re.escape(cond_pattern)}$"})
                else:
                    conditions.append({"field": cond_field, "pattern": f"^{cond_pattern}$"})
            elif cond_type == "or_group":
                for sub in cond_pattern:
                    conditions.append({"field": sub[1], "pattern": sub[2]})
    return conditions


def _try_convert_rule(rule: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        detection = rule.get("detection", {})
        if not detection:
            return None

        logsource = rule.get("logsource", {})
        field_prefix = ""
        for key, mapping in _get_logsource_mapping().items():
            category = logsource.get("category", "")
            product = logsource.get("product", "")
            service = logsource.get("service", "")
            if product == "windows":
                if category and mapping.get("category") == category:
                    field_prefix = mapping.get("field_prefix", "")
                    break
                if service and mapping.get("service") == service:
                    field_prefix = mapping.get("field_prefix", "")
                    break

        conditions = []
        selection = detection.get("selection", {})
        if selection:
            conditions.extend(_convert_selection(selection, field_prefix))

        if not conditions:
            return None

        converted = {
            "id": rule.get("id", ""),
            "title": rule.get("title", "Unknown Rule"),
            "level": rule.get("level", "medium"),
            "description": rule.get("description", ""),
            "conditions": conditions,
            "tags": rule.get("tags", []),
            "false_positives": rule.get("falsepositives", rule.get("false_positives", [])),
            "references": rule.get("references", []),
        }

        return converted
    except Exception as exc:
        logger.debug("Failed to convert rule %s: %s", rule.get("id", "unknown"), exc)
        return None


_logsource_mapping_cache: Optional[Dict[str, Any]] = None


def _get_logsource_mapping() -> Dict[str, Any]:
    global _logsource_mapping_cache
    if _logsource_mapping_cache is not None:
        return _logsource_mapping_cache
    path = Path(__file__).resolve().parent.parent / "data" / "sigma" / "sigma_logsource_map.json"
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                _logsource_mapping_cache = json.load(f)
        except Exception:
            _logsource_mapping_cache = {}
    else:
        _logsource_mapping_cache = {}
    return _logsource_mapping_cache


def load_rules(rules_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    global _rules_cache, _compiled_rules, _field_mega_regexes
    with _cache_lock:
        path = rules_path or _RULES_PATH
        if _rules_cache is not None and _compiled_rules is not None:
            return _rules_cache

        if not path.exists():
            logger.warning("Sigma rules file not found: %s", path)
            _rules_cache = []
            _compiled_rules = []
            return []

        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to load sigma rules: %s", exc)
            _rules_cache = []
            _compiled_rules = []
            return []

        if not isinstance(raw, list):
            _rules_cache = []
            _compiled_rules = []
            return []

        rules = raw
        _rules_cache = rules

        compiled = []
        for rule in rules:
            conditions = rule.get("conditions", [])
            compiled_conditions = []
            event_id_patterns: List[re.Pattern] = []
            valid = True
            for cond in conditions:
                field = cond.get("field", "")
                pattern = cond.get("pattern", "")
                try:
                    regex = re.compile(pattern)
                except re.error as exc:
                    logger.warning(
                        "Bad regex in rule %s (%s) field=%s: %s",
                        rule.get("id", "?"),
                        rule.get("title", "?"),
                        field,
                        exc,
                    )
                    regex = None
                    valid = False
                if _map_field(field) == "event_id":
                    event_id_patterns.append(regex)
                compiled_conditions.append({"field": field, "regex": regex})
            compiled.append({
                "rule": rule,
                "compiled_conditions": compiled_conditions,
                "valid": valid,
                "event_id_patterns": event_id_patterns,
            })

        _compiled_rules = compiled
        _field_mega_regexes = _build_field_mega_regexes(compiled)
        logger.info("Loaded %d sigma rules (%d valid)", len(rules), sum(1 for c in compiled if c["valid"]))
        return rules


def get_compiled_rules() -> List[Dict[str, Any]]:
    if _compiled_rules is None:
        load_rules()
    return _compiled_rules or []


# Map sigma condition field names (PascalCase) to event dict keys (snake_case)
_FIELD_MAP = {
    "AccessList": "access_mask",
    "AccessMask": "access_mask",
    "AccountName": "user_name",
    "AuthenticationPackageName": "auth_package",
    "Channel": "channel",
    "ClientProcessId": "process_id",
    "CommandLine": "command_line",
    "CurrentDirectory": "file_path",
    "Description": "description",
    "DestPort": "dest_port",
    "DestinationHostname": "dest_hostname",
    "DestinationIp": "dest_ip",
    "DestinationPort": "dest_port",
    "Details": "registry_value",
    "ErrorCode": "status_code",
    "EventID": "event_id",
    "ExceptionCode": "status_code",
    "Hash": "hash_value",
    "Hashes": "hash_value",
    "Image": "process_name",
    "ImageLoaded": "file_path",
    "ImagePath": "file_path",
    "ImpersonationLevel": "impersonation_level",
    "IpAddress": "source_ip",
    "Keywords": "keywords",
    "LogonProcessName": "logon_process",
    "LogonType": "logon_type",
    "ObjectName": "object_name",
    "ObjectType": "object_type",
    "OriginalFileName": "original_filename",
    "ParentCommandLine": "parent_command_line",
    "ParentImage": "parent_process",
    "ParentProcessId": "process_id",
    "ParentProcessName": "parent_process",
    "PipeName": "command_line",
    "PreAuthType": "pre_auth_type",
    "ProcessId": "process_id",
    "ProcessName": "process_name",
    "Properties": "properties",
    "Provider_Name": "provider",
    "QueryName": "query_name",
    "RelativeTargetName": "file_path",
    "SamAccountName": "user_name",
    "ServiceFileName": "file_path",
    "ServiceName": "service_name",
    "ShareName": "share_name",
    "SourceImage": "process_name",
    "SourceIp": "source_ip",
    "SourcePort": "source_port",
    "Status": "status_code",
    "SubStatus": "status_code",
    "SubjectUserName": "user_name",
    "TargetFilename": "file_path",
    "TargetImage": "target_process",
    "TargetObject": "registry_key",
    "TargetSid": "target_user_sid",
    "TargetUserName": "target_user",
    "TargetUserSid": "target_user_sid",
    "TaskName": "service_name",
    "TicketEncryptionType": "ticket_encryption_type",
    "TicketOptions": "ticket_options",
    "User": "user_name",
    "UserName": "user_name",
    "Workstation": "hostname",
    "WorkstationName": "hostname",
    "command_line": "command_line",
    "dest_port": "dest_port",
    "event_id": "event_id",
    "parent_process": "parent_process",
    "process_name": "process_name",
    "registry_key": "registry_key",
}


def _map_field(sigma_field: str) -> str:
    return _FIELD_MAP.get(sigma_field, sigma_field)


_field_mega_regexes: Optional[Dict[str, re.Pattern]] = None
_sigma_cache: Dict[Tuple, List[Dict[str, Any]]] = {}
_sigma_cache_lock = threading.Lock()
_SIGMA_CACHE_MAX = 50000
_sigma_cache_hits = 0
_sigma_cache_misses = 0


def _build_field_mega_regexes(compiled_rules: List[Dict[str, Any]]) -> Dict[str, re.Pattern]:
    from collections import defaultdict

    RE_FLAGS = re.compile(r"^\(\?([iLmsux]+)\)")

    patterns: Dict[str, set] = defaultdict(set)
    for entry in compiled_rules:
        for cond in entry.get("compiled_conditions", []):
            regex = cond.get("regex")
            if regex is None:
                continue
            pattern = regex.pattern
            if not pattern:
                continue
            field = _map_field(cond.get("field", ""))
            if field and field != "event_id":
                patterns[field].add(pattern)

    mega: Dict[str, re.Pattern] = {}
    for field, pats in patterns.items():
        if len(pats) < 2:
            continue
        flags = 0
        clean_pats = []
        for p in sorted(pats):
            m = RE_FLAGS.match(p)
            if m:
                fstr = m.group(1)
                if "i" in fstr: flags |= re.IGNORECASE
                if "L" in fstr: flags |= re.LOCALE
                if "m" in fstr: flags |= re.MULTILINE
                if "s" in fstr: flags |= re.DOTALL
                if "u" in fstr: flags |= re.UNICODE
                if "x" in fstr: flags |= re.VERBOSE
                p = p[m.end():]
            clean_pats.append(p)
        combined = "|".join(f"(?:{p})" for p in clean_pats)
        try:
            mega[field] = re.compile(combined, flags)
        except re.error:
            pass
    logger.info("Built %d field mega-regexes for quick rejection", len(mega))
    return mega


def match_event(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    global _field_mega_regexes, _sigma_cache, _sigma_cache_hits, _sigma_cache_misses
    if _field_mega_regexes is None:
        _field_mega_regexes = _build_field_mega_regexes(get_compiled_rules())

    cache_key = (
        event.get("event_id"),
        event.get("command_line"),
        event.get("process_name"),
    )
    with _sigma_cache_lock:
        cached = _sigma_cache.get(cache_key)
    if cached is not None:
        _sigma_cache_hits += 1
        return [dict(m) for m in cached]
    _sigma_cache_misses += 1

    # Quick rejection: if no field's mega-regex matches, no rule can match
    for field, value in event.items():
        if not isinstance(value, str) or not value:
            continue
        mega = _field_mega_regexes.get(field)
        if mega and mega.search(value):
            break
    else:
        with _sigma_cache_lock:
            if len(_sigma_cache) < _SIGMA_CACHE_MAX:
                _sigma_cache[cache_key] = []
        return []

    matches = []
    event_id_str = str(event.get("event_id", ""))
    for entry in get_compiled_rules():
        if not entry["valid"]:
            continue
        eid_patterns = entry.get("event_id_patterns")
        if eid_patterns and not any(p.search(event_id_str) for p in eid_patterns):
            continue
        all_match = True
        for cond in entry["compiled_conditions"]:
            regex = cond["regex"]
            if regex is None:
                all_match = False
                break
            field = _map_field(cond["field"])
            event_value = event.get(field, "")
            if event_value is None:
                event_value = ""
            if not isinstance(event_value, str):
                event_value = str(event_value)
            if not regex.search(event_value):
                all_match = False
                break
        if all_match:
            rule = entry["rule"]
            tags = rule.get("tags", [])
            mitre_techniques = []
            for tag in tags:
                tag_lower = tag.lower()
                if tag_lower in _MITRE_MAP:
                    mitre_techniques.append({"id": tag_lower, "name": _MITRE_MAP[tag_lower]})
                elif tag_lower.startswith("attack."):
                    mitre_techniques.append({"id": tag_lower, "name": tag_lower.split(".")[-1]})

            matches.append({
                "id": rule.get("id", "unknown"),
                "title": rule.get("title", "Unknown Rule"),
                "level": rule.get("level", "medium"),
                "description": rule.get("description", ""),
                "tags": tags,
                "mitre_techniques": mitre_techniques,
                "false_positives": rule.get("false_positives", []),
            })

    with _sigma_cache_lock:
        if len(_sigma_cache) < _SIGMA_CACHE_MAX:
            _sigma_cache[cache_key] = matches
    return matches


def get_cache_stats() -> Dict[str, Any]:
    global _sigma_cache_hits, _sigma_cache_misses
    with _sigma_cache_lock:
        size = len(_sigma_cache)
    return {"size": size, "hits": _sigma_cache_hits, "misses": _sigma_cache_misses}

def clear_cache() -> None:
    global _rules_cache, _compiled_rules, _field_mega_regexes, _sigma_cache, _sigma_cache_hits, _sigma_cache_misses
    with _cache_lock:
        _rules_cache = None
        _compiled_rules = None
        _field_mega_regexes = None
    with _sigma_cache_lock:
        _sigma_cache.clear()
        _sigma_cache_hits = 0
        _sigma_cache_misses = 0
