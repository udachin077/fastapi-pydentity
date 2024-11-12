from fastapi import FastAPI
from pydentity.authentication import AuthenticationSchemeProvider, AuthenticationError
from starlette.responses import PlainTextResponse
from starlette.types import ExceptionHandler

from fastapi_pydentity.authentication.dependency import AuthenticationOptionsAccessor
from fastapi_pydentity.authentication.options import AUTHENTICATION_OPTIONS
from fastapi_pydentity.authentication.builder import AuthenticationBuilder
from fastapi_pydentity.authentication.middleware import AuthenticationMiddleware
from fastapi_pydentity.http import HttpContext


def add_authentication(default_scheme: str | None = None):
    return AuthenticationBuilder(default_scheme)


def use_authentication(app: FastAPI, raise_error: bool = False, on_error: ExceptionHandler | None = None):
    app.add_middleware(
        AuthenticationMiddleware,
        context=HttpContext,
        schemes=AuthenticationSchemeProvider(AuthenticationOptionsAccessor(AUTHENTICATION_OPTIONS)),
        raise_error=raise_error
    )
    if on_error:
        app.add_exception_handler(AuthenticationError, on_error)
    else:
        app.add_exception_handler(
            AuthenticationError,
            lambda req, exc: PlainTextResponse("Forbidden", status_code=403)
        )
