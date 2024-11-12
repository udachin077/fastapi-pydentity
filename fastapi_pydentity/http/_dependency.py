from typing import Annotated

from fastapi import Depends
from pydentity.http.context import HttpContext as _HttpContext, IHttpContextAccessor
from pydentity.security.claims import ClaimsPrincipal
from starlette.requests import Request
from starlette.responses import Response

from fastapi_pydentity.authentication.dependency import IAuthenticationSchemeProviderDepends


class HttpContext(_HttpContext):
    def __init__(
            self,
            request: Request,
            response: Response,
            schemes: IAuthenticationSchemeProviderDepends
    ):
        super().__init__(request, response, schemes)

    def _getuser(self) -> ClaimsPrincipal | None:
        return self.request.user

    def _setuser(self, value: ClaimsPrincipal | None) -> None:
        self.request.scope["user"] = value


HttpContextDepends = Annotated[_HttpContext, Depends(HttpContext)]


class HttpContextAccessor(IHttpContextAccessor):
    def __init__(self, context: HttpContextDepends):
        super().__init__(context)


IHttpContextAccessorDepends = Annotated[IHttpContextAccessor, Depends(HttpContextAccessor)]
