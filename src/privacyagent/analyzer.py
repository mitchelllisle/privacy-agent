from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from privacyagent.models import PiiMatch


def walk_values(data: Any, path: str = "$") -> Iterator[tuple[str, Any]]:
    if isinstance(data, dict):
        for key, value in data.items():
            yield from walk_values(value, f"{path}.{key}")
        return

    if isinstance(data, list):
        for idx, value in enumerate(data):
            yield from walk_values(value, f"{path}[{idx}]")
        return

    yield path, data


def _build_detection_context(data: Any) -> tuple[str, int]:
    lines: list[str] = []
    scanned = 0

    for path, value in walk_values(data):
        if value is None or isinstance(value, bool):
            continue
        scanned += 1
        lines.append(f"{path}: {value}")

    payload = "\n".join(lines)
    return payload, scanned


def _build_detection_chunks(data: Any, chunk_size: int = 60) -> tuple[list[str], int, dict[str, str]]:
    lines: list[str] = []
    scanned = 0
    values: dict[str, str] = {}

    for path, value in walk_values(data):
        if value is None or isinstance(value, bool):
            continue
        scanned += 1
        text = str(value)
        lines.append(f"{path}: {text}")
        values[path] = text

    if not lines:
        return [], scanned, values

    chunks = ["\n".join(lines[i : i + chunk_size]) for i in range(0, len(lines), chunk_size)]
    return chunks, scanned, values


def _item_get(item: Any, key: str) -> Any:
    if isinstance(item, dict):
        return item.get(key)
    return getattr(item, key, None)


def analyze_pii_with_agent(data: Any) -> tuple[list[PiiMatch], int]:
    chunks, fields_scanned, _values = _build_detection_chunks(data)

    if not chunks:
        return [], fields_scanned

    from baml_client.sync_client import b  # type: ignore

    collected: list[PiiMatch] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()

    for chunk in chunks:
        response = b.DetectPIIWithContext(
            context=chunk,
            system_instructions=(
                "Classify only values that are likely PII. Return precise paths and avoid false positives."
            ),
        )

        if isinstance(response, list):
            raw_matches = response
        elif hasattr(response, "matches"):
            raw_matches = getattr(response, "matches", [])
        else:
            raw_matches = []

        for item in raw_matches:
            path = str(_item_get(item, "path") or "")
            if not path:
                continue

            plural_types = _item_get(item, "types") or _item_get(item, "pii_types") or []
            singular_type = _item_get(item, "pii_type")
            normalized_types = [str(t).strip() for t in plural_types if str(t).strip()]
            if singular_type and str(singular_type).strip() and not normalized_types:
                normalized_types = [str(singular_type).strip()]
            if not normalized_types:
                continue

            dedupe_key = (path, tuple(sorted(normalized_types)))
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            collected.append(
                PiiMatch(
                    path=path,
                    pii_types=normalized_types,
                    confidence=_item_get(item, "confidence"),
                    reason=str(_item_get(item, "reason") or ""),
                )
            )

    return collected, fields_scanned
