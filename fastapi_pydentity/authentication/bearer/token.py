from collections.abc import Iterable, Generator
from datetime import timedelta, datetime
from typing import Any

import jwt
from jwt.exceptions import InvalidKeyError, ExpiredSignatureError
from pydentity.security.claims import Claim

from fastapi_pydentity.authentication.bearer.types import KeyType


def _generate_claims(payload: dict[str, Any]) -> Generator[Claim]:
    for key, value in payload.items():
        if key in ("aud", "exp", "iat", "iss", "jti", "nbf", "sub",):
            continue

        if isinstance(value, list):
            yield from (Claim(key, v) for v in value)
        else:
            yield Claim(key, value)


class JWTSecurityToken(dict[str, Any]):
    def __init__(
            self,
            signin_key: KeyType,
            algorithm: str = "HS256",
            audience: str | None = None,
            claims: Iterable[Claim] | None = None,
            expires: datetime | int | None = None,
            headers: dict[str, Any] | None = None,
            issuer: str | None = None,
            issuer_at: datetime | int | None = None,
            not_before: datetime | int | None = None,
            subject: str | None = None,
            **kwargs
    ) -> None:
        super().__init__()
        self.__signing_key = signin_key
        self.algorithm = algorithm
        self.headers = headers
        self.claims = claims
        self.update(kwargs)
        self.expires = expires
        self.not_before = not_before
        self.audience = audience
        self.issuer = issuer
        self.issuer_at = issuer_at
        self.subject = subject

    @property
    def audience(self) -> str | None:
        return self.get("aud")

    @audience.setter
    def audience(self, value: str | None) -> None:
        self._set_or_remove("aud", value)

    @property
    def expires(self) -> datetime | int | None:
        return self.get("exp")

    @expires.setter
    def expires(self, value: datetime | int | None) -> None:
        self._set_or_remove("exp", value)

    @property
    def issuer(self) -> str | None:
        return self.get("iss")

    @issuer.setter
    def issuer(self, value: str | None) -> None:
        self._set_or_remove("iss", value)

    @property
    def issuer_at(self) -> datetime | int | None:
        return self.get("iat")

    @issuer_at.setter
    def issuer_at(self, value: datetime | int | None) -> None:
        self._set_or_remove("iat", value)

    @property
    def not_before(self) -> datetime | int | None:
        return self.get("nbf")

    @not_before.setter
    def not_before(self, value: datetime | int | None) -> None:
        self._set_or_remove("nbf", value)

    @property
    def subject(self) -> str | None:
        return self.get("sub")

    @subject.setter
    def subject(self, value: str | None) -> None:
        self._set_or_remove("sub", value)

    def _set_or_remove(self, key: str, value: Any) -> None:
        if value is not None:
            self[key] = value
        elif key in self:
            del self[key]

    def _set_claims(self) -> None:
        for claim in self.claims:
            if value := self.get(claim.type):
                if isinstance(value, list):
                    self[claim.type].append(claim.value)
                else:
                    self[claim.type] = [value, claim.value]
            else:
                self[claim.type] = claim.value

    def encode(self) -> str:
        if self.expires and self.not_before and self.not_before >= self.expires:
            raise ExpiredSignatureError(f"Expires: '{self.expires}' must be after not_before: '{self.not_before}'.")

        if not self.__signing_key:
            raise InvalidKeyError()

        if self.claims:
            self._set_claims()

        return jwt.encode(self, self.__signing_key, self.algorithm, self.headers)

    @staticmethod
    def decode(
            token: str | bytes,
            key: KeyType,
            algorithms: list[str] | None = None,
            options: dict[str, Any] | None = None,
            audience: str | Iterable[str] | None = None,
            issuer: str | list[str] | None = None,
            leeway: float | timedelta = 0
    ) -> "JWTSecurityToken":
        payload = jwt.decode(
            token,
            key,
            algorithms=algorithms or ["HS256"],
            audience=audience,
            issuer=issuer,
            options=options,
            leeway=leeway
        )
        return JWTSecurityToken(
            signin_key=key,
            claims=[*_generate_claims(payload)] or None,
            **payload
        )
