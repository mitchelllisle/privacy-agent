from fastapi import FastAPI, HTTPException

from privacyagent import __version__
from privacyagent.config import Settings
from privacyagent.models import RunRequest
from privacyagent.service import PrivacyService

# Validate required configuration during app import/startup.
settings = Settings()

app = FastAPI(title="Privacy Agent", version=__version__)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.post("/run")
def run(request: RunRequest) -> dict:
    service = PrivacyService()
    try:
        threshold = request.config.threshold if request.config else None
        return_matches = request.config.return_matches if request.config else True
        result = service.run(
            request.data,
            threshold=threshold,
            return_matches=return_matches,
        )
    except Exception as exc:
        # Surface the real upstream/model failure to callers in a structured way.
        raise HTTPException(
            status_code=502,
            detail=f"{type(exc).__name__}: {exc}",
        ) from exc
    return result.model_dump(exclude_none=True)
