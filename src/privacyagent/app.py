from fastapi import FastAPI, HTTPException

"""FastAPI application wiring for the privacy agent service."""

from privacyagent import __version__
from privacyagent.config import Settings
from privacyagent.models import RunRequest
from privacyagent.service import PrivacyService

# Validate required configuration during app import/startup.
settings = Settings()

app = FastAPI(title="Privacy Agent", version=__version__)


@app.get("/health")
def health() -> dict[str, str]:
    """Return basic service health metadata.

    Returns:
        A dictionary containing service status and version.
    """
    return {"status": "ok", "version": __version__}


@app.post("/run")
def run(request: RunRequest) -> dict:
    """Run PII detection for the provided payload.

    Args:
        request: API request containing `data` and optional run config.

    Returns:
        A serialized run result with counts and optional matches.

    Raises:
        HTTPException: Raised with 502 when upstream model processing fails.
    """
    service = PrivacyService()
    try:
        threshold = request.config.threshold if request.config else None
        return_matches = request.config.return_matches if request.config else True
        review = request.config.review if request.config else False
        result = service.run(
            request.data,
            threshold=threshold,
            return_matches=return_matches,
            review=review,
        )
    except Exception as exc:
        # Surface the real upstream/model failure to callers in a structured way.
        raise HTTPException(
            status_code=502,
            detail=f"{type(exc).__name__}: {exc}",
        ) from exc
    return result.model_dump(exclude_none=True)
