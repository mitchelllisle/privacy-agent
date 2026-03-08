from fastapi import FastAPI, HTTPException

from classifyagent import __version__
from classifyagent.config import Settings
from classifyagent.models import RunRequest
from classifyagent.service import ClassificationService

# Validate required configuration during app import/startup.
settings = Settings()

app = FastAPI(title="Classification Agent", version=__version__)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.post("/run")
def run(request: RunRequest) -> dict:
    service = ClassificationService()
    try:
        result = service.run(request.payload)
    except Exception as exc:
        # Surface upstream model failures to callers in a structured way.
        raise HTTPException(
            status_code=502,
            detail=f"{type(exc).__name__}: {exc}",
        ) from exc

    return result.model_dump(exclude_none=True)
