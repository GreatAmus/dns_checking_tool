import re
from dataclasses import dataclass
from typing import Literal, Optional

# Invalid user input base error
class InvalidTarget(ValueError):
    """Base error for invalid user input targets."""

# Invalid domain name
class InvalidDomain(InvalidTarget):
    """Raised when a target is not a valid domain/zone."""

# Normalize the user input by trumming white space and removing trailing dots and turning it into lower case.
def normalize_target(raw: str) -> str:
    return (raw or "").strip().rstrip(".").lower()

# Check to ensure the provided domain is a valid domain. Checks only format not existence
_LABEL = re.compile(r"^_?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
def is_domain(s: str) -> bool:
    if not s or len(s) > 253 or any(c.isspace() for c in s):
        return False

    labels = s.split(".")
    if any(label == "" or len(label) > 63 for label in labels):
        return False

    return all(_LABEL.match(label) for label in labels)

# normalizes text and checks to see if it is a domain
def require_domain(raw: str) -> str:
    s = normalize_target(raw)
    if not is_domain(s):
        raise InvalidDomain("Invalid domain format")
    return s