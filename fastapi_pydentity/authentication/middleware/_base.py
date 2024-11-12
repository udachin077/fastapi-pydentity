from fastapi.requests import Request
from pydentity.authentication import AuthenticationError
from pydentity.authentication.interfaces import IAuthenticationSchemeProvider
from pydentity.http.context import HttpContext
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp, Scope, Receive, Send

__all__ = ("AuthenticationMiddleware",)


class AuthenticationMiddleware(BaseHTTPMiddleware):
    __slots__ = ("app", "context", "schemes", "raise_error",)

    def __init__(
            self,
            app: ASGIApp,
            context: type[HttpContext],
            schemes: IAuthenticationSchemeProvider,
            raise_error: bool = False
    ) -> None:
        super().__init__(app)
        self.app = app
        self.context = context
        self.schemes = schemes
        self.raise_error = raise_error

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ["http", "websocket"]:
            await self.app(scope, receive, send)
            return

        scope["user"] = None
        scope["auth"] = False

        context = self.context(Request(scope), None, self.schemes)

        try:
            default_authenticate = await self.schemes.get_default_authentication_scheme()

            if default_authenticate:
                result = await context.authenticate(default_authenticate.name)

                if result.principal and result.principal.identities:
                    scope["user"] = result.principal
                    scope["auth"] = result.principal.identity.is_authenticated

        except AuthenticationError as exc:
            if self.raise_error:
                raise exc

        await self.app(scope, receive, send)
