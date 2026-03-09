# Privacy Agent

Privacy classification service that accepts a REST POST payload and returns which values appear to contain PII.

## Current behavior

- `GET /health` returns service health.
- `POST /run` accepts JSON under `data` and sends flattened field context to a BAML privacy agent.
- The BAML agent uses Claude Sonnet for structured PII extraction.
- Detection is LLM-only and requires a working BAML client plus provider API key.
- App startup fails fast if required environment variables are missing.
- Response includes matched field paths, detected PII types, and optional confidence/reason.
- Response does not include raw input values to avoid propagating PII.
- Optional request `config.threshold` filters out matches below the confidence threshold.
- Optional request `config.return_matches` controls whether `matches` are returned (default `true`).
- Response always includes top-level `types` with per-type counts.

## Local development

```bash
uv sync
uv run pytest
uv run python -m privacyagent.__main__
```

To generate/update the BAML Python client locally:

```bash
uv run baml-cli generate
```

Example request:

```bash
curl -X POST http://localhost:8080/run \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "email": "alice@example.com",
      "phone": "+1 415 555 0101",
      "notes": "card 4242 4242 4242 4242"
    }
  }'
```

## Cloud Run deploy

```bash
gcloud builds submit --tag gcr.io/$GOOGLE_CLOUD_PROJECT/privacy-agent
gcloud run deploy privacy-agent \
  --image gcr.io/$GOOGLE_CLOUD_PROJECT/privacy-agent \
  --platform managed \
  --region australia-southeast1 \
  --allow-unauthenticated
```

## Environment variables

- `ANTHROPIC_API_KEY` for Claude Sonnet BAML calls.
- `OPENAI_API_KEY` optional if you later add OpenAI clients to BAML.
