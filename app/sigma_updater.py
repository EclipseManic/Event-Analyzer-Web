"""Sigma community rule updater for Event-Analyzer.

Downloads and converts Sigma rules from the official SigmaHQ repository and
community repositories to the Event-Analyzer format.

Usage:
    python scripts/sigma_updater.py              # Fetch and convert all rules
    python scripts/sigma_updater.py --dry-run    # Show what would be added without writing
    python scripts/sigma_updater.py --force      # Re-fetch even if rules file is up to date
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
import urllib.request
from pathlib import Path
import io
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

BASE_DIR = Path(__file__).resolve().parent.parent
RULES_PATH = BASE_DIR / "data" / "sigma" / "sigma_rules.json"
LOGSOURCE_MAP_PATH = BASE_DIR / "data" / "sigma" / "sigma_logsource_map.json"

_LOGSOURCE_MAP: Dict[str, Any] = {}

# ── Repository sources ──────────────────────────────────────────────
# Each entry describes a source of Sigma rules: a GitHub archive ZIP
# and a filter function to identify rule YAML files within it.

RepoSource = Dict[str, Any]


def _sigma_prefix_filter(prefix: str) -> Callable[[str], bool]:
    """Create a filter that accepts YAML/YML files nested under a given zip prefix."""
    def _filter(path: str) -> bool:
        if not path.startswith(prefix):
            return False
        if not (path.endswith(".yml") or path.endswith(".yaml")):
            return False
        if path.endswith("/.") or path.endswith("/.."):
            return False
        rest = path[len(prefix):].lstrip("/")
        if not rest or "/" not in rest:
            return False
        return True
    return _filter


def _any_prefix_filter(prefixes: List[str]) -> Callable[[str], bool]:
    """Accept YAML files nested under any of the given zip prefixes."""
    filters = [_sigma_prefix_filter(p) for p in prefixes]
    def _filter(path: str) -> bool:
        return any(f(path) for f in filters)
    return _filter


REPO_SOURCES: List[RepoSource] = [
    # ── SigmaHQ/sigma — only Windows rules (EVTX-only tool) ──
    {
        "name": "SigmaHQ/sigma (windows)",
        "zip_url": "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip",
        "rule_filter": _any_prefix_filter(["sigma-master/rules/windows/"]),
    },
    # ── mdecrevoisier/SIGMA-detection-rules ──
    {
        "name": "mdecrevoisier/SIGMA-detection-rules",
        "zip_url": "https://github.com/mdecrevoisier/SIGMA-detection-rules/archive/refs/heads/main.zip",
        "rule_filter": _any_prefix_filter(["SIGMA-detection-rules-main/"]),
    },
    # ── joesecurity/sigma-rules ──
    {
        "name": "joesecurity/sigma-rules",
        "zip_url": "https://github.com/joesecurity/sigma-rules/archive/refs/heads/master.zip",
        "rule_filter": _any_prefix_filter(["sigma-rules-master/"]),
    },
    # ── Yamato-Security/hayabusa-rules ──
    {
        "name": "Yamato-Security/hayabusa-rules",
        "zip_url": "https://github.com/Yamato-Security/hayabusa-rules/archive/refs/heads/main.zip",
        "rule_filter": _any_prefix_filter(["hayabusa-rules-main/"]),
    },
]


def _load_logsource_map() -> Dict[str, Any]:
    global _LOGSOURCE_MAP
    if _LOGSOURCE_MAP:
        return _LOGSOURCE_MAP
    try:
        with open(LOGSOURCE_MAP_PATH, "r", encoding="utf-8") as f:
            _LOGSOURCE_MAP = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        _LOGSOURCE_MAP = {}
    return _LOGSOURCE_MAP


def _download_repo_zip(url: str, name: str, timeout: int = 90) -> Optional[bytes]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Event-Analyzer/1.0"})
        print(f"  Downloading from {name} ...")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        print(f"    {len(data)} bytes")
        return data
    except Exception as exc:
        print(f"    [ERROR] {exc}")
        return None


def _parse_sigma_yml(content: str, filepath: str) -> Optional[Dict[str, Any]]:
    try:
        import yaml
    except ImportError:
        print("PyYAML is required. Install with: pip install pyyaml")
        return None

    try:
        data = yaml.safe_load(content)
    except Exception as exc:
        print(f"  [WARN] YAML parse error in {filepath}: {exc}")
        return None

    if not isinstance(data, dict):
        return None

    rule_id = data.get("id", "")
    if not rule_id:
        rule_id = Path(filepath).stem

    title = data.get("title", "").strip()
    if not title:
        return None

    level = data.get("level", "medium")
    description = (data.get("description") or "").strip()

    detection = data.get("detection", {})
    if not detection:
        return None

    logsource = data.get("logsource", {})
    logsource_category = logsource.get("category", "")

    tags = data.get("tags", []) or []
    false_positives = data.get("falsepositives", data.get("false_positives", [])) or []
    if not isinstance(false_positives, list):
        false_positives = [str(false_positives)]

    references = data.get("references", []) or []
    if not isinstance(references, list):
        references = [str(references)]

    converted = {
        "id": rule_id,
        "title": title,
        "level": level,
        "description": description,
        "detection": detection,
        "logsource": logsource,
        "tags": tags,
        "false_positives": false_positives,
        "references": references,
    }

    conditions = _convert_detection(detection, logsource_category)
    if not conditions:
        return None

    converted["conditions"] = conditions
    return converted


def _convert_detection(
    detection: Any, logsource_category: str
) -> List[Dict[str, str]]:
    if not isinstance(detection, dict):
        return []
    conditions = []
    logsource_map = _load_logsource_map()
    field_prefix = ""

    for key, mapping in logsource_map.items():
        if mapping.get("category") == logsource_category:
            field_prefix = mapping.get("field_prefix", "")
            break

    selection = detection.get("selection")
    if not isinstance(selection, dict):
        # Try to find a selection key that is a dict
        selection = None
        for key in detection:
            if key.startswith("selection") and isinstance(detection[key], dict):
                selection = detection[key]
                break
        if not isinstance(selection, dict):
            # Fallback: use the whole detection dict if it's a dict
            if isinstance(detection, dict):
                selection = detection
            else:
                return []

    for field, value in selection.items():
        if not isinstance(field, str) or field.startswith("|"):
            continue
        clean_field, modifier = (field.split("|", 1) + [""])[:2]
        prefixed = f"{field_prefix}{clean_field}" if field_prefix else clean_field

        if modifier == "re" and isinstance(value, str):
            conditions.append({"field": prefixed, "pattern": value})
        elif modifier == "contains" and isinstance(value, str):
            conditions.append({"field": prefixed, "pattern": re.escape(value)})
        elif modifier == "startswith" and isinstance(value, str):
            conditions.append({"field": prefixed, "pattern": "^" + re.escape(value)})
        elif modifier == "endswith" and isinstance(value, str):
            conditions.append({"field": prefixed, "pattern": re.escape(value) + "$"})
        elif isinstance(value, str):
            conditions.append({"field": prefixed, "pattern": "^" + re.escape(value) + "$"})
        elif isinstance(value, (int, float)):
            conditions.append({"field": prefixed, "pattern": f"^{value}$"})
        elif isinstance(value, list):
            value_conditions = []
            for item in value:
                if isinstance(item, (int, float, str)):
                    escaped = re.escape(str(item))
                    value_conditions.append(escaped)
            if value_conditions:
                pattern = "^(?:" + "|".join(value_conditions) + ")$"
                conditions.append({"field": prefixed, "pattern": pattern})

    return conditions


def _load_existing_rules() -> List[Dict[str, Any]]:
    if not RULES_PATH.exists():
        return []
    try:
        with open(RULES_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _save_rules(rules: List[Dict[str, Any]]) -> None:
    RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(RULES_PATH, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"Saved {len(rules)} rules to {RULES_PATH}")


def _is_rule_included(converted: Dict[str, Any], existing_ids: Set[str]) -> bool:
    rule_id = converted.get("id")
    if not rule_id:
        return False
    if rule_id in existing_ids:
        return False
    conditions = converted.get("conditions", [])
    if not conditions:
        return False
    for cond in conditions:
        try:
            re.compile(cond.get("pattern", ""))
        except re.error:
            return False
    return True


def _get_rule_name(filepath: str) -> str:
    # Strip known repo root prefixes to get a clean relative path
    known_prefixes = [
        "sigma-master/rules/",
        "SIGMA-detection-rules-main/",
        "sigma-rules-master/",
        "hayabusa-rules-main/",
        "Sigma-Rules-main/",
    ]
    for prefix in known_prefixes:
        if filepath.startswith(prefix):
            rel = filepath[len(prefix):]
            return rel.replace("\\", "/")
    # Fallback: just use the filename
    return Path(filepath).name


def _process_repo(
    source: RepoSource,
    existing_ids: Set[str],
    rules_list: List[Dict[str, Any]],
    dry_run: bool,
    force: bool,
) -> Tuple[int, int, int]:
    """Process a single repo source, returning (new, skipped, errors)."""
    zip_data = _download_repo_zip(source["zip_url"], source["name"])
    if not zip_data:
        return 0, 0, 0

    new = 0
    skipped = 0
    errors = 0
    seen = 0
    rule_filter = source["rule_filter"]

    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
        candidates = [f for f in zf.namelist() if rule_filter(f)]
        print(f"    Found {len(candidates)} candidate YAML files")

        for filepath in candidates:
            seen += 1
            try:
                content = zf.read(filepath).decode("utf-8", errors="replace")
            except Exception:
                errors += 1
                continue

            converted = _parse_sigma_yml(content, filepath)
            if not converted:
                errors += 1
                continue

            if _is_rule_included(converted, existing_ids):
                rules_list.append(converted)
                existing_ids.add(converted["id"])
                new += 1
            else:
                skipped += 1

            if seen % 500 == 0:
                print(f"      Progress: {seen}/{len(candidates)} ({new} new, {skipped} skipped, {errors} errors)")

    return new, skipped, errors


def update_rules(dry_run: bool = False, force: bool = False) -> int:
    try:
        import yaml
    except ImportError:
        print("PyYAML is required. Install with: pip install pyyaml")
        return 0

    existing = _load_existing_rules()
    existing_ids = {r["id"] for r in existing if r.get("id")}

    print(f"Existing rules: {len(existing)} ({len(existing_ids)} unique IDs)")
    print()

    total_new = 0
    total_skipped = 0
    total_errors = 0

    for source in REPO_SOURCES:
        print(f"-- {source['name']} --")
        new, skipped, errors = _process_repo(source, existing_ids, existing, dry_run, force)
        total_new += new
        total_skipped += skipped
        total_errors += errors
        print(f"    -> {new} new, {skipped} skipped, {errors} errors")
        print()

    print(f"{'=' * 50}")
    print(f"Overall: {total_new} new, {total_skipped} skipped, {total_errors} errors")
    print(f"Total rules in file: {len(existing)}")

    if total_new > 0 and not dry_run:
        _save_rules(existing)
    elif dry_run and total_new > 0:
        print("  (dry-run — no changes written)")

    return total_new


def run(dry_run: bool = False, force: bool = False) -> int:
    return update_rules(dry_run=dry_run, force=force)


def main() -> None:
    parser = argparse.ArgumentParser(description="Sigma community rule updater")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be added without writing")
    parser.add_argument("--force", action="store_true", help="Re-fetch even if rules file is up to date")
    args = parser.parse_args()

    print("Sigma Community Rule Updater")
    print(f"Rules path: {RULES_PATH}")
    print()

    try:
        import yaml
    except ImportError:
        print("PyYAML is required. Install with: pip install pyyaml")
        sys.exit(1)

    count = update_rules(dry_run=args.dry_run, force=args.force)
    if count == 0:
        print("No new rules added.")
    else:
        print(f"Added {count} new rules.")

    print("Done.")


if __name__ == "__main__":
    main()
