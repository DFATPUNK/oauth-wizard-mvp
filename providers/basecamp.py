"""Basecamp provider implementation for the OAuth wizard."""
from __future__ import annotations

import re
from typing import Optional


_CLIENT_ID_PATTERN = re.compile(r"^[0-9A-Fa-f]{32}$")


class BasecampProvider:
    """Minimal Basecamp provider with credential validation helpers."""

    id = "basecamp"
    name = "Basecamp"
    authorize_endpoint: Optional[str] = None
    token_endpoint: Optional[str] = None
    userinfo_endpoint: Optional[str] = None
    tokeninfo_endpoint: Optional[str] = None

    def validate_client_id(self, client_id: str) -> bool:
        """Return ``True`` if *client_id* looks like a Basecamp identifier.

        Basecamp client IDs are 32-character hexadecimal strings. Historically we
        only accepted lowercase characters which caused valid uppercase IDs to be
        rejected. The validation now accepts both uppercase and lowercase hex
        digits.
        """

        if not isinstance(client_id, str):
            return False
        normalized = client_id.strip()
        if not normalized:
            return False
        return bool(_CLIENT_ID_PATTERN.fullmatch(normalized))

    def validate_client_secret(self, client_secret: str) -> bool:
        return isinstance(client_secret, str) and len(client_secret.strip()) > 0


provider = BasecampProvider()