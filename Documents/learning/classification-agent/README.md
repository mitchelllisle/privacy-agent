# Classification Agent

Data classification service that accepts a structured payload and returns a classification per item.

## Current behavior

- `GET /health` returns service health.
- `POST /run` accepts JSON in the form `{"payload": [{"name", "description", "samples"}]}`.
- The BAML agent uses Claude Sonnet for structured sensitivity classification.
- App startup fails fast if required environment variables are missing.
- Response format is `{"classifications": [{"name", "classification", "rationale", "confidence"}]}`.
- Confidence is a float between `0` and `1` when returned by the model.

## Local development

```bash
uv sync
uv run pytest
uv run python -m classifyagent.__main__
```

To generate or refresh the BAML Python client locally:

```bash
uv run baml-cli generate
```

Example request:

```bash
curl -X POST http://localhost:8080/run \
	-H "Content-Type: application/json" \
	-d '{
		"payload": [
			{
				"name": "customer_email",
				"description": "Email for account communication",
				"samples": ["alice@example.com", "bob@example.com"]
			},
			{
				"name": "marketing_banner_copy",
				"description": "Homepage hero message",
				"samples": ["Save 20% this week"]
			}
		]
	}'
```

## Environment variables

- `ANTHROPIC_API_KEY` for Claude Sonnet BAML calls.
- `OPENAI_API_KEY` optional if you later add OpenAI clients to BAML.
