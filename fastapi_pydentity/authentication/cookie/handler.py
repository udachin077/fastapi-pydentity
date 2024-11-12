import json
import sys
from functools import lru_cache
from typing import Any

from pydentity.authentication import DefaultAuthenticationDataProtector, AuthenticationResult
from pydentity.authentication.interfaces import IAuthenticationHandler, IAuthenticationDataProtector
from pydentity.http.context import HttpContext
from pydentity.security.claims import ClaimsPrincipal
from pydentity.security.claims.serializer import principal_serialize, principal_deserialize
from pydentity.utils import datetime

from fastapi_pydentity.authentication.cookie.cookie_options import CookieAuthenticationOptions


@lru_cache
def _get_cookie_name(scheme: str, name: str | None = None) -> str:
    return name or scheme


@lru_cache
def _split_on_chunks(key: str, value: str, max_size: int = 4090) -> dict[str, str]:
    if sys.getsizeof(value) <= max_size:
        return {key: value}

    chunks = [value[i:i + max_size] for i in range(0, len(value), max_size)]
    _chunks = {key: f"chunks-{len(chunks)}"}
    _chunks.update({f"{key}C{i + 1}": chunk for i, chunk in enumerate(chunks)})
    return _chunks


@lru_cache
def _join_from_chunks(cookies: dict[str, str], key: str) -> str:
    chunks_count = int(cookies.get(key).removeprefix("chunks-"))
    return "".join(cookies[f"{key}C{i + 1}"] for i in range(chunks_count))


def _get_expires(properties: dict[str, Any], options: CookieAuthenticationOptions) -> datetime | None:
    if properties.get("is_persistent"):
        return datetime.utcnow().add(options.persistent_timespan)
    elif options.timespan:
        return datetime.utcnow().add(options.timespan)
    return None


class DefaultCookieAuthenticationProtector(DefaultAuthenticationDataProtector):
    pass


class CookieAuthenticationHandler(IAuthenticationHandler):
    __slots__ = ("options", "protector",)

    def __init__(
            self,
            options: CookieAuthenticationOptions | None = None,
            protector: IAuthenticationDataProtector | None = None
    ) -> None:
        self.options = options or CookieAuthenticationOptions()
        self.protector = protector or DefaultCookieAuthenticationProtector()

    async def authenticate(self, context: HttpContext, scheme: str) -> AuthenticationResult:
        return self._decode_authentication_cookie(scheme, context.request.cookies)

    async def sign_in(self, context: HttpContext, scheme: str, principal: ClaimsPrincipal, **properties) -> None:
        context.response.headers["Cache-Control"] = "no-cache,no-store"
        context.response.headers["Pragma"] = "no-cache"

        cookies = self._encode_authentication_cookie(scheme, principal, **properties)

        for key, value in cookies.items():
            context.response.set_cookie(
                key=key,
                value=value,
                expires=_get_expires(properties, self.options),
                httponly=self.options.httponly,
                secure=self.options.secure,
                samesite=self.options.samesite,
                domain=self.options.domain
            )

    async def sign_out(self, context: HttpContext, scheme: str) -> None:
        for key in context.request.cookies:
            if key.startswith(_get_cookie_name(scheme, self.options.name)):
                context.response.delete_cookie(key)

    def _encode_authentication_cookie(self, scheme: str, principal: ClaimsPrincipal, **properties) -> dict[str, str]:
        data = {"principal": principal_serialize(principal)}

        if properties:
            data.update({"..properties": properties})

        protected_data = self.protector.protect(json.dumps(data, separators=(',', ':',)))
        key = _get_cookie_name(scheme, self.options.name)
        return _split_on_chunks(key, protected_data)

    def _decode_authentication_cookie(self, scheme: str, cookies: dict[str, str]) -> AuthenticationResult:
        key = _get_cookie_name(scheme, self.options.name)

        if value := cookies.get(key):
            if value.startswith("chunks-"):
                value = _join_from_chunks(cookies, key)

            unprotected_data = json.loads(self.protector.unprotect(value))
            properties = unprotected_data.pop("..properties", {})
            if p := unprotected_data.pop("principal"):
                principal = principal_deserialize(p)
            else:
                principal = ClaimsPrincipal()
            return AuthenticationResult(principal, properties)

        return AuthenticationResult(ClaimsPrincipal(), {})
