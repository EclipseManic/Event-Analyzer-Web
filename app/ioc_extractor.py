"""IOC extraction for Event-Analyzer."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional

from app.logger import get_logger

logger = get_logger("ioc_extractor")

_IOC_PATTERNS = {
    "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
    "hash": r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{128})\b",
    "url": r"https?://(?:[^\s\"'<>]+)",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "filepath": r"[a-zA-Z]:\\(?:[^\\\"]+\\)*[^\\\"]*\.(?:exe|dll|ps1|bat|cmd|vbs|js|py|jar|tmp|dat)",
    "registry": r"(?:HK[A-Z][A-Z]\\|HKEY_[A-Z_]+)(?:[^\\]+\\)*[^\\]+",
}
_IP_RE = re.compile(_IOC_PATTERNS["ip"])
_DOMAIN_RE = re.compile(_IOC_PATTERNS["domain"])
_HASH_RE = re.compile(_IOC_PATTERNS["hash"])
_URL_RE = re.compile(_IOC_PATTERNS["url"])
_EMAIL_RE = re.compile(_IOC_PATTERNS["email"])
_FILEPATH_RE = re.compile(_IOC_PATTERNS["filepath"])
_REGISTRY_RE = re.compile(_IOC_PATTERNS["registry"])
_IOC_MEGA_RE = re.compile("|".join(f"(?P<{k}>{v})" for k, v in _IOC_PATTERNS.items()))

_PROCESS_NAME_RE = re.compile(r"(?:^|\\)([^\\\"]+)\.(?:exe|dll|ps1|bat|cmd|vbs|js|py|jar)", re.IGNORECASE)

_CONTEXT_VERSION_INDICATORS = {
    "version", "ver.", "build", "release", "sdk", "api",
    "framework", "runtime", "library", "package",
    "1.0.", "2.0.", "3.0.", "4.0.", "5.0.", "6.0.", "7.0.", "8.0.", "9.0.",
    ".net", "netcore", "v1.", "v2.", "v3.", "v4.",
}

WINDOWS_INFRA_DOMAINS: set = {
    "crl.microsoft.com", "ocsp.digicert.com", "ocsp.verisign.com",
    "ocsp.comodoca.com", "ocsp.entrust.net", "ocsp.godaddy.com",
    "cacerts.digicert.com", "certs.verisign.com",
    "ctldl.windowsupdate.com", "download.windowsupdate.com",
    "update.microsoft.com",
    "windowsupdate.com", "windowsupdate.microsoft.com",
    "delivery.mp.microsoft.com", "fe3cr.delivery.mp.microsoft.com",
    "geo-prod.do.dsp.mp.microsoft.com",
    "displaycatalog.mp.microsoft.com",
    "store-images.s-microsoft.com",
    "settings-win.data.microsoft.com", "settings.data.microsoft.com",
    "vortex.data.microsoft.com", "v10.vortex-win.data.microsoft.com",
    "vortex-win.data.microsoft.com",
    "watson.telemetry.microsoft.com",
    "telecommand.telemetry.microsoft.com",
    "oca.telemetry.microsoft.com",
    "sqm.telemetry.microsoft.com",
    "sls.update.microsoft.com", "licensing.mp.microsoft.com",
    "definitionupdates.microsoft.com",
    "client.wns.windows.com", "notify.windows.com",
    "store-images.microsoft.com",
    "img-prod-cms-rt-microsoft-com.azureedge.net",
    "officeclient.microsoft.com",
    "onegetcdn.azureedge.net",
    "arc.msn.com",
    "ris-prod-atm.trafficmanager.net",
}


_INFRA_DOMAIN_DOTTED = frozenset("." + d for d in WINDOWS_INFRA_DOMAINS)


def _is_infra_domain(domain: str) -> bool:
    if domain in WINDOWS_INFRA_DOMAINS:
        return True
    return any(domain.endswith(s) for s in _INFRA_DOMAIN_DOTTED)


def _is_version_string(token: str) -> bool:
    digits = token.replace(".", "")
    if not digits.isdigit():
        return False
    parts = token.split(".")
    return len(parts) >= 3 or (len(parts) == 2 and all(len(p) == 1 for p in parts))


def _is_valid_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
        parts = token.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


_EXCLUDED_IPS = {"0.0.0.0", "255.255.255.255", "127.0.0.1"}

_FILE_EXTENSIONS = frozenset({
    ".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".py", ".jar",
    ".tmp", ".dat", ".xml", ".json", ".csv", ".txt", ".doc", ".docx",
    ".xls", ".xlsx", ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz",
    ".msi", ".msp", ".ocx", ".sys", ".drv", ".com", ".scr", ".pif",
    ".wsf", ".wsh", ".psm1", ".psd1", ".rb", ".php", ".asp", ".aspx",
    ".jsp", ".cfg", ".conf", ".ini", ".log", ".evtx",
})

_DOTNET_NAMESPACES = frozenset({
    "microsoft", "system", "windows", "management", "automation",
    "collections", "linq", "text", "io", "net", "security",
    "diagnostics", "reflection", "runtime", "componentmodel",
})

_BENIGN_PROCESSES = frozenset({
    "system", "smss", "csrss", "wininit", "winlogon",
    "fontdrvhost", "lsaiso",
})


def _is_likely_domain(token: str) -> bool:
    parts = token.rsplit(".", 1)
    if len(parts) != 2:
        return False
    tld = parts[1].lower()
    if len(tld) < 2:
        return False
    if f".{tld}" in _FILE_EXTENSIONS:
        return False
    if "_" in token:
        return False
    if token.count(".") > 4:
        return False
    first_part = parts[0].lower()
    if first_part in _DOTNET_NAMESPACES:
        return False
    if any(ns in first_part for ns in _DOTNET_NAMESPACES if len(ns) >= 6):
        return False
    return True


def extract_iocs(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    iocs: List[Dict[str, Any]] = []
    seen: set = set()

    text_fields = [
        ("command_line", event.get("command_line", "")),
        ("description", event.get("description", "")),
        ("process_name", event.get("process_name", "")),
    ]

    value = ""
    for field_name, field_value in text_fields:
        if not field_value:
            continue
        value = str(field_value)

        for match in _IOC_MEGA_RE.finditer(value):
            ioc_type = match.lastgroup
            token = match.group()
            start = max(0, match.start() - 60)
            end = min(len(value), match.end() + 60)
            match_context = value[start:end].strip()
            if start > 0:
                match_context = "…" + match_context
            if end < len(value):
                match_context = match_context + "…"

            if ioc_type == "ip":
                if token in _EXCLUDED_IPS:
                    continue
                if not _is_valid_ip(token):
                    continue
                if _is_version_string(token):
                    continue
                key = f"ip:{token}"
                if key not in seen:
                    seen.add(key)
                    iocs.append({
                        "ioc_type": "ip",
                        "value": token,
                        "source": field_name,
                        "context": match_context[:200],
                    })

            elif ioc_type == "hash":
                hlen = len(token)
                if hlen not in (32, 40, 64, 128):
                    continue
                key = f"hash:{token}"
                if key not in seen:
                    seen.add(key)
                    htype = "MD5" if hlen == 32 else "SHA1" if hlen == 40 else "SHA256"
                    iocs.append({
                        "ioc_type": "hash",
                        "value": token,
                        "source": field_name,
                        "context": f"[{htype}] {match_context}"[:200],
                    })

            elif ioc_type == "filepath":
                key = f"filepath:{token.lower()}"
                if key not in seen:
                    seen.add(key)
                    iocs.append({
                        "ioc_type": "file",
                        "value": token,
                        "source": field_name,
                        "context": match_context[:200],
                    })

            elif ioc_type == "registry":
                key = f"registry:{token.lower()}"
                if key not in seen:
                    seen.add(key)
                    iocs.append({
                        "ioc_type": "registry",
                        "value": token,
                        "source": field_name,
                        "context": match_context[:200],
                    })

            elif ioc_type == "domain":
                if _is_infra_domain(token):
                    continue
                if not _is_likely_domain(token):
                    continue
                key = f"domain:{token.lower()}"
                if key not in seen:
                    seen.add(key)
                    iocs.append({
                        "ioc_type": "domain",
                        "value": token,
                        "source": field_name,
                        "context": match_context[:200],
                    })

            elif ioc_type == "url":
                token = token.rstrip(".,;:!?)")
                if len(token) > 512:
                    continue
                domain_match = _DOMAIN_RE.search(token)
                if domain_match and _is_infra_domain(domain_match.group()):
                    continue
                key = f"url:{token}"
                if key not in seen:
                    seen.add(key)
                    iocs.append({
                        "ioc_type": "url",
                        "value": token,
                        "source": field_name,
                        "context": match_context[:200],
                    })

            elif ioc_type == "email":
                key = f"email:{token.lower()}"
                if key not in seen:
                    seen.add(key)
                    iocs.append({
                        "ioc_type": "email",
                        "value": token,
                        "source": field_name,
                        "context": match_context[:200],
                    })

    for match in _PROCESS_NAME_RE.finditer(value):
        if field_name == "description":
            continue
        pname = match.group(1)
        if not pname or len(pname) < 2:
            continue
        if pname.lower() in _BENIGN_PROCESSES:
            continue
        key = f"process:{pname.lower()}"
        if key not in seen:
            seen.add(key)
            pi = match.start()
            pctx_start = max(0, pi - 60)
            pctx_end = min(len(value), match.end() + 60)
            pctx = value[pctx_start:pctx_end].strip()
            if pctx_start > 0:
                pctx = "…" + pctx
            if pctx_end < len(value):
                pctx = pctx + "…"
            iocs.append({
                "ioc_type": "process",
                "value": pname,
                "source": field_name,
                "context": pctx[:200],
            })

    desc = event.get("description", "")

    source_ip = event.get("source_ip", "")
    dest_ip = event.get("dest_ip", "")
    if source_ip:
        key = f"srcip:{source_ip}"
        if key not in seen:
            seen.add(key)
            iocs.append({
                "ioc_type": "ip",
                "value": source_ip,
                "source": "source_ip",
                "context": (desc or f"Source IP: {source_ip}")[:200],
            })
    if dest_ip:
        key = f"dstip:{dest_ip}"
        if key not in seen:
            seen.add(key)
            iocs.append({
                "ioc_type": "ip",
                "value": dest_ip,
                "source": "dest_ip",
                "context": (desc or f"Dest IP: {dest_ip}")[:200],
            })

    fv = event.get("file_path", "")
    if fv:
        key = f"field:file_path:{fv}"
        if key not in seen:
            seen.add(key)
            iocs.append({
                "ioc_type": "file",
                "value": fv,
                "source": "file_path",
                "context": (desc or f"File: {fv}")[:200],
            })

    registry_key = event.get("registry_key", "")
    if registry_key:
        key = f"reg:{registry_key}"
        if key not in seen:
            seen.add(key)
            iocs.append({
                "ioc_type": "registry",
                "value": registry_key,
                "source": "registry_key",
                "context": (desc or f"Registry: {registry_key}")[:200],
            })

    hash_value = event.get("hash_value", "")
    if hash_value:
        key = f"hash_field:{hash_value}"
        if key not in seen:
            seen.add(key)
            iocs.append({
                "ioc_type": "hash",
                "value": hash_value,
                "source": "hash_value",
                "context": (desc or f"Hash: {hash_value}")[:200],
            })

    return iocs
