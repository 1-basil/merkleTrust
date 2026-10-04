"""core/analyzers — format-specific analysers for non-APK content.

Each module exposes the engine contract ``run(job_id, ctx) -> dict`` and writes
``content.json`` (engine name "content"). ``run`` here dispatches on
``ctx.file_category`` (set by the orchestrator from core.detector).
"""

from __future__ import annotations

from core.analyzers import document, image, media, web
from core.contracts import EngineError, JobContext

ANALYZERS = {
    "image": image.run,
    "video": media.run,
    "audio": media.run,
    "web": web.run,
    "doc": document.run,
}


def run(job_id: str, ctx: JobContext) -> dict:
    analyzer = ANALYZERS.get(ctx.file_category)
    if analyzer is None:
        raise EngineError(f"No content analyser for category '{ctx.file_category}'")
    return analyzer(job_id, ctx)
