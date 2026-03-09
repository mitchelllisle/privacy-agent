# Privacy Agent

PII detection service that accepts a REST POST payload and returns which values appear to contain PII.

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

## Request/response examples

### 1) Basic detection

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

Example response:

```json
{
  "fields_scanned": 3,
  "fields_matched": 3,
  "types": [
    {"type": "credit_card", "count": 1},
    {"type": "email", "count": 1},
    {"type": "phone_number", "count": 1}
  ],
  "matches": [
    {
      "path": "$.email",
      "types": ["email"],
      "confidence": 0.98,
      "reason": "Matches a standard email pattern and key semantics."
    },
    {
      "path": "$.phone",
      "types": ["phone_number"],
      "confidence": 0.97,
      "reason": "Matches phone pattern with supporting key name."
    },
    {
      "path": "$.notes",
      "types": ["credit_card"],
      "confidence": 0.92,
      "reason": "Contains a credit card-like sequence."
    }
  ]
}
```

### 2) Field-name context (column name awareness)

The detector evaluates both value patterns and field-path semantics. In this payload, `email` is likely PII, while address-like fields under `residential`, `mailing`, and `office` may have lower confidence or no match depending on policy and context.

```json
{
  "data": {
    "email": "hello@hello.com",
    "residential": {
      "street": "12 Fake Street",
      "suburb": "Sydney"
    },
    "mailing": {
      "street": "12 Fake Street",
      "suburb": "Sydney"
    },
    "office": {
      "street": "5 Pitt Street",
      "suburb": "Sydney"
    }
  }
}
```

Possible response:

```json
{
  "fields_scanned": 7,
  "fields_matched": 4,
  "types": [
    {
      "type": "address",
      "count": 3
    },
    {
      "type": "email",
      "count": 1
    }
  ],
  "matches": [
    {
      "path": "$.email",
      "types": [
        "email"
      ],
      "confidence": 0.95,
      "reason": "Valid email format with field name 'email' confirming type"
    },
    {
      "path": "$.residential.street",
      "types": [
        "address"
      ],
      "confidence": 0.85,
      "reason": "Street address format with 'residential.street' field path indicating home address"
    },
    {
      "path": "$.mailing.street",
      "types": [
        "address"
      ],
      "confidence": 0.85,
      "reason": "Street address format with 'mailing.street' field path indicating postal address"
    },
    {
      "path": "$.office.street",
      "types": [
        "address"
      ],
      "confidence": 0.85,
      "reason": "Street address format with 'office.street' field path indicating work address"
    }
  ]
}
```

If your policy treats street/suburb values as sensitive, adjust prompts and confidence threshold accordingly.

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
