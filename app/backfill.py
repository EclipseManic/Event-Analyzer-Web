"""One-time backfill: extract IOCs and Sigma matches for existing investigations."""

from __future__ import annotations

from app import db
from app.ioc_extractor import extract_iocs
from app.logger import get_logger
from app.sigma_matcher import load_rules, match_event

logger = get_logger("backfill")


def backfill_investigation(inv_id: str, batch_size: int = 500) -> dict:
    offset = 0
    limit = 1000
    total_iocs = 0
    total_sigma = 0
    total_events = 0

    while True:
        events = db.get_events(inv_id, limit=limit, offset=offset)
        if not events:
            break

        ioc_batch: list[dict] = []
        sigma_batch: list[dict] = []

        for event in events:
            try:
                for ioc in extract_iocs(event):
                    ioc["investigation_id"] = inv_id
                    ioc["event_id"] = event.get("id")
                    ioc_batch.append(ioc)
            except Exception as exc:
                logger.warning("IOC extraction failed for event %s: %s", event.get("id", "?"), exc)

            try:
                for m in match_event(event):
                    sigma_batch.append({
                        "investigation_id": inv_id,
                        "event_id": event.get("id"),
                        "rule_id": m.get("id"),
                        "rule_title": m.get("title"),
                        "level": m.get("level"),
                        "description": m.get("description"),
                        "mitre_techniques": m.get("mitre_techniques", []),
                    })
            except Exception as exc:
                logger.warning("Sigma matching failed for event %s: %s", event.get("id", "?"), exc)

        if ioc_batch:
            db.insert_iocs_bulk(ioc_batch)
            total_iocs += len(ioc_batch)
        if sigma_batch:
            db.insert_sigma_bulk(sigma_batch)
            total_sigma += len(sigma_batch)

        total_events += len(events)
        offset += limit
        logger.info("  Processed %d events ...", total_events)

    return {"events": total_events, "iocs": total_iocs, "sigma": total_sigma}


def run() -> None:
    db.init_db()
    load_rules()

    investigations = db.list_investigations()
    if not investigations:
        logger.info("No investigations found.")
        return

    logger.info("Found %d investigations", len(investigations))

    for inv in investigations:
        inv_id = inv["id"]
        name = inv.get("name", "?")
        logger.info("Backfilling: %s (%s)", name, inv_id)
        result = backfill_investigation(inv_id)
        logger.info(
            "  Done: %d events, %d IOCs, %d Sigma matches",
            result["events"],
            result["iocs"],
            result["sigma"],
        )


if __name__ == "__main__":
    run()
