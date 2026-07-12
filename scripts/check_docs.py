#!/usr/bin/env python3
"""Validate local Markdown links and normative identifier uniqueness."""

from __future__ import annotations

import re
import sys
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
NORMATIVE_ID = re.compile(r"^\| ((?:FR|SR|UXR|TR|NFR)-\d{3}) \|", re.MULTILINE)
REQUIRED = {
    "README.md",
    "docs/PRD.md",
    "docs/SPECIFICATION.md",
    "docs/THREAT_MODEL.md",
    "docs/TECHNICAL_REQUIREMENTS.md",
    "docs/TECHNICAL_DESIGN.md",
    "docs/POLICY_MODEL.md",
    "docs/IMPLEMENTATION_PLAN.md",
    "docs/TECHNICAL_PLAN.md",
    "docs/TEST_STRATEGY.md",
    "docs/TRACEABILITY.md",
    "docs/USER_GUIDE.md",
    "docs/DEMO.md",
    "docs/adr/README.md",
    "CHANGELOG.md",
}


def markdown_files() -> list[Path]:
    return sorted(path for path in ROOT.rglob("*.md") if ".git" not in path.parts)


def check_required(errors: list[str]) -> None:
    for relative in sorted(REQUIRED):
        if not (ROOT / relative).is_file():
            errors.append(f"missing required document: {relative}")


def check_links(files: list[Path], errors: list[str]) -> None:
    for source in files:
        text = source.read_text(encoding="utf-8")
        for target in MARKDOWN_LINK.findall(text):
            target = target.strip().split("#", 1)[0]
            if not target or target.startswith(("http://", "https://", "mailto:")):
                continue
            if target.startswith("<") and target.endswith(">"):
                target = target[1:-1]
            resolved = (source.parent / target).resolve()
            try:
                resolved.relative_to(ROOT)
            except ValueError:
                errors.append(f"{source.relative_to(ROOT)}: link escapes repository: {target}")
                continue
            if not resolved.exists():
                errors.append(f"{source.relative_to(ROOT)}: missing local link target: {target}")


def check_identifiers(files: list[Path], errors: list[str]) -> None:
    occurrences: list[tuple[str, Path]] = []
    for source in files:
        text = source.read_text(encoding="utf-8")
        occurrences.extend((identifier, source) for identifier in NORMATIVE_ID.findall(text))

    counts = Counter(identifier for identifier, _ in occurrences)
    for identifier, count in sorted(counts.items()):
        if count > 1:
            locations = sorted(
                str(path.relative_to(ROOT)) for found, path in occurrences if found == identifier
            )
            errors.append(f"duplicate normative ID {identifier}: {', '.join(locations)}")

    required_prefixes = {"FR", "SR", "UXR", "TR", "NFR"}
    found_prefixes = {identifier.split("-", 1)[0] for identifier in counts}
    for prefix in sorted(required_prefixes - found_prefixes):
        errors.append(f"no normative identifiers found for prefix {prefix}")


def check_schemas(errors: list[str]) -> None:
    schemas = sorted((ROOT / "schemas").glob("*.schema.json"))
    if len(schemas) < 3:
        errors.append("expected policy, audit, and red-team JSON schemas")
    for schema in schemas:
        try:
            value = json.loads(schema.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            errors.append(f"{schema.relative_to(ROOT)}: invalid JSON schema: {error}")
            continue
        if value.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            errors.append(f"{schema.relative_to(ROOT)}: must declare JSON Schema 2020-12")
        if not value.get("$id") or not value.get("title"):
            errors.append(f"{schema.relative_to(ROOT)}: missing $id or title")


def main() -> int:
    errors: list[str] = []
    files = markdown_files()
    check_required(errors)
    check_links(files, errors)
    check_identifiers(files, errors)
    check_schemas(errors)

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1

    print(f"documentation checks passed ({len(files)} Markdown files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
