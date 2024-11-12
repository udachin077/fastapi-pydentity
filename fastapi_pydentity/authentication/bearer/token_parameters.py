from collections.abc import Iterable
from datetime import timedelta
from typing import Any

from fastapi_pydentity.authentication.bearer.types import KeyType


class TokenValidationParameters:
    """
    Contains a set of parameters that are used by a JWTBearerAuthenticationHandler when validating a security token.
    """

    __slots__ = (
        "issuer_signing_key",
        "leeway",
        "options",
        "valid_algorithms",
        "valid_audiences",
        "valid_issuers",
    )

    def __init__(
            self,
            issuer_signing_key: KeyType,
            valid_algorithms: list[str] | None = None,
            valid_audiences: str | Iterable[str] | None = None,
            valid_issuers: str | list[str] | None = None,
            options: dict[str, Any] | None = None,
            leeway: float | timedelta = 0
    ) -> None:
        self.issuer_signing_key = issuer_signing_key
        self.valid_algorithms = valid_algorithms or ["HS256"]
        self.valid_audiences = valid_audiences
        self.valid_issuers = valid_issuers
        self.options = options
        self.leeway = leeway
