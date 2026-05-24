"""
Excel worksheet name sanitization and deduplication.

Excel constraints:
  - Maximum 31 characters
  - Characters [ ] : * ? / \\ are not allowed
  - Sheet names are case-insensitive for uniqueness purposes
"""

import re

_INVALID_CHARS = re.compile(r"[\[\]:*?/\\]")
MAX_LEN = 31


def sanitize_sheet_name(name: str) -> str:
    """Remove invalid Excel characters, strip whitespace, and truncate to 31 chars."""
    name = _INVALID_CHARS.sub("_", name).strip()
    return (name or "Sheet")[:MAX_LEN]


def make_unique_sheet_names(names: list[str]) -> list[str]:
    """
    Return a list of sanitized, unique sheet names.

    Duplicates (case-insensitive) get a numeric suffix: name, name_2, name_3 …
    All names are guaranteed to be ≤ 31 characters.
    """
    used: set[str] = set()
    result: list[str] = []

    for name in names:
        sanitized = sanitize_sheet_name(name)
        lower = sanitized.lower()

        if lower not in used:
            used.add(lower)
            result.append(sanitized)
        else:
            counter = 2
            while True:
                suffix = f"_{counter}"
                base = sanitized[: MAX_LEN - len(suffix)]
                candidate = base + suffix
                if candidate.lower() not in used:
                    used.add(candidate.lower())
                    result.append(candidate)
                    break
                counter += 1

    return result
