# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Lock classification at ingest time.

Runs the lock over a pair's string-valued slots as the pair is ingested and
persists the classification plus a pre-scrubbed ``clean`` block on the pair,
so safe-context queries read pre-computed data instead of re-scanning::

    raw text → triples + fingerprint + facets → lock_classify_pair() (once)
        → pair.lock  = {classified_at, audit, total_findings, ...}
        → pair.clean = {fingerprint (scrubbed), triples (scrubbed)}

If a cached classification is older than the current disclaimer version, the
cached scrub is suspect and a live re-scrub is due.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Optional

from . import host_deps

LOCK_DISCLAIMER_VERSION = "v1"   # bump when lock rules change


def _lock_string(text: str, context: str = "") -> dict[str, Any]:
    """One-shot wrapper around :func:`.core.lock_text`; any failure refuses."""
    if not text:
        return {"action": "allow", "text": "", "findings": 0}
    try:
        from .core import Mode, lock_text
        decision = lock_text(text, context=context, mode=Mode.STANDARD,
                             source="triple")
        if decision.action == "allow":
            return {"action": "allow", "text": text,
                    "findings": len(decision.findings)}
        if decision.action == "minimise":
            return {"action": "minimise",
                    "text": decision.redacted_text or "",
                    "findings": len(decision.findings)}
        return {"action": "refuse",
                "text": "[LOCK-REFUSED]",
                "findings": len(decision.findings),
                "reason": decision.reason}
    except Exception as e:
        return {"action": "refuse",
                "text": "[LOCK-UNAVAILABLE]",
                "findings": 0,
                "reason": f"lock_text unavailable: {type(e).__name__}: {e}"}


# Facet keys the safe-context surface considers structural (taxonomy).
_SAFE_FACET_KEYS = {
    "domain", "subject", "modal", "modal_phrase", "language",
    "has_condition", "has_exception", "primary_type",
}


def _doc_token_fn(folder_path: str) -> Callable[[Optional[str]], str]:
    """Bind the host's per-folder opaque doc-token hook; absent → ``<DOC_unknown>``."""
    host_deps.ensure_wired()
    hook = host_deps.opaque_doc_token

    def fn(src: Optional[str]) -> str:
        if not src:
            return "<DOC_NONE>"
        if hook is None:
            return "<DOC_unknown>"
        try:
            return str(hook(src, folder_path))
        except Exception:
            return "<DOC_unknown>"
    return fn


def lock_classify_pair(pair: dict[str, Any],
                       folder_context: str,
                       *,
                       context: str = "") -> dict[str, Any]:
    """Return a NEW pair dict enriched with ``lock`` + ``clean`` blocks; the
    input is left unchanged. Original fields are the dirty side (raw bodies);
    ``clean`` is the pre-scrubbed safe view."""
    new_pair = dict(pair)
    problem = pair.get("problem") or {}
    solution = pair.get("solution") or {}
    facets = problem.get("facets") or {}
    doc_token = _doc_token_fn(folder_context)

    safe_facets_raw = {k: facets[k] for k in _SAFE_FACET_KEYS if k in facets}
    raw_summary = problem.get("summary") or ""
    ptype = problem.get("type") or ""
    if ptype == "document_ingest":
        src = problem.get("source_document") or raw_summary
        summary_raw = f"document {doc_token(src)}"
    else:
        summary_raw = raw_summary

    summary_scrub = _lock_string(summary_raw, context=context)
    facets_scrub: dict[str, dict[str, Any]] = {}
    clean_facets: dict[str, Any] = {}
    facets_dropped = 0
    for k, v in safe_facets_raw.items():
        if isinstance(v, str) and v:
            r = _lock_string(v, context=context)
            facets_scrub[k] = r
            if r["action"] == "refuse":
                facets_dropped += 1
                continue
            clean_facets[k] = r["text"]
        else:
            clean_facets[k] = v
            facets_scrub[k] = {"action": "allow", "findings": 0,
                               "type": type(v).__name__}

    clean_fingerprint = {
        "scope":          problem.get("scope") or "",
        "type":           ptype,
        "summary":        summary_scrub["text"]
                          if summary_scrub["action"] != "refuse"
                          else "[LOCK-REFUSED]",
        "facets":         clean_facets,
        "authority_tier": solution.get("authority_tier"),
        "confidence":     solution.get("confidence"),
        "body_format":    solution.get("body_format"),
    }

    # Triples — every string object scrubbed. Structured solution slots become
    # triples directly, so a reader sees the knowledge without the body.
    pid = pair.get("id") or "?"
    ctx_block = problem.get("context") or {}
    raw_triples: list[list[Any]] = []
    if problem.get("kind"):  raw_triples.append([pid, "kind",  problem.get("kind")])
    if problem.get("scope"): raw_triples.append([pid, "scope", problem.get("scope")])
    if ptype:                raw_triples.append([pid, "type",  ptype])
    for k in ("domain", "subject", "modal", "modal_phrase", "language",
              "has_condition", "has_exception", "primary_type",
              "term", "ref_kind", "ref_number", "doc_kind", "doc_id"):
        if k in facets:
            raw_triples.append([pid, k, facets[k]])
    for k in ("regulation", "kind_of_model", "doc_kind"):
        if k in ctx_block:
            raw_triples.append([pid, k, ctx_block[k]])
    for list_key in ("domains", "jurisdictions", "actors"):
        for v in (ctx_block.get(list_key) or []):
            raw_triples.append([pid, list_key + "_includes", v])
    for k in ("term", "defined_as", "ref_kind", "ref_number", "regulation",
              "doc_kind", "doc_id", "summary_excerpt"):
        if k in solution and solution[k] not in (None, ""):
            raw_triples.append([pid, k, solution[k]])
    if solution.get("authority_tier") is not None:
        raw_triples.append([pid, "authority_tier", solution["authority_tier"]])
    src = problem.get("source_document")
    if src:
        raw_triples.append([pid, "source_document", doc_token(src)])

    clean_triples: list[list[Any]] = []
    triples_dropped = 0
    triple_audit: list[dict[str, Any]] = []
    total_findings = summary_scrub.get("findings", 0)
    for s, p, o in raw_triples:
        if isinstance(o, str) and o:
            r = _lock_string(o, context=context)
            total_findings += r.get("findings", 0) or 0
            if r["action"] == "refuse":
                triples_dropped += 1
                triple_audit.append({"predicate": p, "action": "refuse",
                                     "reason": r.get("reason", "")})
                continue
            clean_triples.append([s, p, r["text"]])
            if r["action"] == "minimise":
                triple_audit.append({"predicate": p, "action": "minimise",
                                     "findings": r["findings"]})
        else:
            clean_triples.append([s, p, o])

    # Body — dirty-side only; the lock still runs for the audit count.
    body = solution.get("body")
    body_scrub_summary: dict[str, Any] = {"action": "n/a", "findings": 0}
    if isinstance(body, str) and body:
        r = _lock_string(body, context=context)
        body_scrub_summary = {"action": r["action"],
                              "findings": r.get("findings", 0)}
        total_findings += r.get("findings", 0) or 0

    new_pair["lock"] = {
        "classified_at":      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "disclaimer_version": LOCK_DISCLAIMER_VERSION,
        "total_findings":     total_findings,
        "triples_dropped":    triples_dropped,
        "facets_dropped":     facets_dropped,
        "audit_triples":      triple_audit,
        "audit_summary":      {"action": summary_scrub["action"],
                               "findings": summary_scrub.get("findings", 0)},
        "audit_body":         body_scrub_summary,
    }
    new_pair["clean"] = {
        "fingerprint": clean_fingerprint,
        "triples":     clean_triples,
    }
    return new_pair


def reclassify_all_pairs(folder_context: str,
                         *,
                         log_root: str | None = None,
                         actor: str = "lock-reclassify",
                         memory: Any = None) -> dict[str, Any]:
    """Re-classify every pair in a folder when lock rules change.

    ``memory`` (or the host's ``workspace_memory`` hook) exposes ``all_pairs()``
    and ``remember(pair, channel=, source_hash=)``; the enriched pair is written
    back and most-recent-state-wins yields the new version.
    """
    if memory is None:
        host_deps.ensure_wired()
        if host_deps.workspace_memory is None:
            raise RuntimeError("reclassify_all_pairs needs a memory port "
                               "(argument or host_deps.workspace_memory)")
        memory = host_deps.workspace_memory(folder_context, log_root=log_root, actor=actor)
    pairs = memory.all_pairs()
    n_updated = 0
    n_skipped = 0
    for p in pairs:
        existing = p.get("lock") or {}
        if existing.get("disclaimer_version") == LOCK_DISCLAIMER_VERSION:
            n_skipped += 1
            continue
        enriched = lock_classify_pair(p, folder_context)
        memory.remember(enriched, channel="system",
                        source_hash=p.get("id", "").replace("sha256:", ""))
        n_updated += 1
    return {
        "ok": True,
        "folder_context": folder_context,
        "pairs_total": len(pairs),
        "pairs_reclassified": n_updated,
        "pairs_already_current": n_skipped,
        "disclaimer_version": LOCK_DISCLAIMER_VERSION,
    }
