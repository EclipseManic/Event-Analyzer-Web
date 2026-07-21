"""EVTX ingestion pipeline for the viewer."""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

from app.evtx_parser import parse_evtx_file
from app.ioc_extractor import extract_iocs
from app.logger import get_logger
from app.mitre_mapper import map_event
from app.sigma_matcher import match_event, get_cache_stats
from app import db
from app.config import get_config

logger = get_logger("ingest")


@dataclass
class IngestResult:
    total_events: int
    files_processed: List[str]
    errors: List[str]


def _update_progress(inv_id: str, stage: str, detail: str, percent: int) -> None:
    try:
        db.set_analysis_progress(inv_id, stage, detail, percent)
    except Exception:
        pass


def _cleanup_source_file(path: str) -> None:
    if not get_config().delete_after_ingest:
        return
    try:
        p = Path(path)
        if not p.exists():
            return
        p.unlink(missing_ok=True)
        parent = p.parent
        if parent.exists() and not any(parent.iterdir()):
            parent.rmdir()
    except Exception:
        pass


def ingest_files(
    investigation_id: str,
    file_paths: Iterable[str],
    max_events_per_file: int = 0,
    store_raw: bool = False,
    batch_size: int = 2000,
    stop_event: Optional[threading.Event] = None,
) -> IngestResult:
    files = [str(Path(p)) for p in file_paths]
    total_files = len(files)
    total_events = 0
    processed: List[str] = []
    errors: List[str] = []
    import time
    _t0 = time.perf_counter()
    _t_parse = 0.0
    _t_analyze = 0.0
    _t_db = 0.0
    _t_fts = 0.0

    db.update_investigation(investigation_id, status="processing")

    for idx, path in enumerate(files, start=1):
        if stop_event and stop_event.is_set():
            break

        percent = int(((idx - 1) / max(1, total_files)) * 100)
        _update_progress(investigation_id, "parsing", f"{Path(path).name} ({idx}/{total_files})", percent)

        _t_file0 = time.perf_counter()

        batch: List[dict] = []
        ioc_batch: List[dict] = []
        sigma_batch: List[dict] = []
        file_events = 0
        next_event_num = total_events + 1
        try:
            events_iter = parse_evtx_file(path, investigation_id, max_events=max_events_per_file)
            _t_parse += time.perf_counter() - _t_file0

            def _analyze(evt: dict) -> tuple:
                try:
                    mitre_tags = map_event(evt)
                    if mitre_tags:
                        evt["mitre_techniques"] = mitre_tags
                except Exception:
                    pass

                iocs = []
                try:
                    for ioc in extract_iocs(evt):
                        ioc["investigation_id"] = investigation_id
                        ioc["event_id"] = evt.get("id")
                        iocs.append(ioc)
                except Exception as exc:
                    logger.warning("IOC extraction failed for event %s: %s", evt.get("id", "?"), exc)

                detections = []
                try:
                    for m in match_event(evt):
                        detections.append({
                            "investigation_id": investigation_id,
                            "event_id": evt.get("id"),
                            "rule_id": m.get("id"),
                            "rule_title": m.get("title"),
                            "level": m.get("level"),
                            "description": m.get("description"),
                            "mitre_techniques": json.dumps(m.get("mitre_techniques", [])),
                        })
                except Exception as exc:
                    logger.warning("Sigma matching failed for event %s: %s", evt.get("id", "?"), exc)

                return evt, iocs, detections

            _t_a0 = time.perf_counter()
            with ThreadPoolExecutor(max_workers=4) as pool:
                pending = set()
                for evt in events_iter:
                    if stop_event and stop_event.is_set():
                        break
                    pending.add(pool.submit(_analyze, evt))
                    if len(pending) >= 200:
                        for future in as_completed(pending):
                            event, event_iocs, event_sigma = future.result()
                            ioc_batch.extend(event_iocs)
                            sigma_batch.extend(event_sigma)
                            batch.append(event)
                            if len(batch) >= batch_size:
                                _t_db0 = time.perf_counter()
                                db.insert_events_bulk(batch, skip_fts=True, commit=False, start_number=next_event_num)
                                if ioc_batch:
                                    db.insert_iocs_bulk(ioc_batch, commit=False)
                                    ioc_batch.clear()
                                if sigma_batch:
                                    db.insert_sigma_bulk(sigma_batch, commit=False)
                                    sigma_batch.clear()
                                db.commit()
                                _t_db += time.perf_counter() - _t_db0
                                total_events += len(batch)
                                file_events += len(batch)
                                next_event_num += len(batch)
                                batch.clear()
                        pending = set()
                for future in as_completed(pending):
                    if stop_event and stop_event.is_set():
                        break
                    event, event_iocs, event_sigma = future.result()
                    ioc_batch.extend(event_iocs)
                    sigma_batch.extend(event_sigma)
                    batch.append(event)
            if batch:
                _t_db0 = time.perf_counter()
                db.insert_events_bulk(batch, skip_fts=True, commit=False, start_number=next_event_num)
                if ioc_batch:
                    db.insert_iocs_bulk(ioc_batch, commit=False)
                if sigma_batch:
                    db.insert_sigma_bulk(sigma_batch, commit=False)
                db.commit()
                _t_db += time.perf_counter() - _t_db0
                total_events += len(batch)
                file_events += len(batch)
                batch.clear()
            _t_a_elapsed = time.perf_counter() - _t_a0
            _t_analyze += _t_a_elapsed
            _t_fts0 = time.perf_counter()
            try:
                db.rebuild_fts(investigation_id)
            except Exception as exc:
                logger.warning("FTS rebuild failed: %s", exc)
            _t_fts += time.perf_counter() - _t_fts0
        except Exception as exc:
            err = f"{Path(path).name}: {exc}"
            errors.append(err)
            logger.error(err)
            _cleanup_source_file(path)
            continue

        processed.append(Path(path).name)
        db.update_investigation(
            investigation_id,
            total_events=total_events,
            files_processed=processed,
        )
        _update_progress(
            investigation_id,
            "parsed",
            f"{Path(path).name}: {file_events} events",
            int((idx / max(1, total_files)) * 100),
        )
        _cleanup_source_file(path)

    status = "complete" if not errors else "complete_with_errors"
    try:
        stats = get_cache_stats()
        logger.info("Sigma cache: size=%d hits=%d misses=%d (hit ratio=%.1f%%)",
                     stats['size'], stats['hits'], stats['misses'],
                     stats['hits'] / max(1, stats['hits'] + stats['misses']) * 100)
    except Exception:
        pass

    _t1 = time.perf_counter()
    logger.info("TIMING total=%.1fs parse=%.1fs analyze=%.1fs db_insert=%.1fs fts_rebuild=%.1fs",
                _t1 - _t0, _t_parse, _t_analyze, _t_db, _t_fts)
    db.update_investigation(investigation_id, status=status, total_events=total_events)
    _update_progress(investigation_id, status, "done", 100)

    return IngestResult(total_events=total_events, files_processed=processed, errors=errors)
