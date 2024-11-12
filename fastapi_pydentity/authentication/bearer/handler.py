import logging

from jwt.exceptions import PyJWTError
from pydentity.authentication import AuthenticationResult
from pydentity.authentication.interfaces import IAuthenticationHandler
from pydentity.http.context import HttpContext
from pydentity.security.claims import ClaimsPrincipal, ClaimsIdentity

from fastapi_pydentity.authentication.bearer.token import JWTSecurityToken
from fastapi_pydentity.authentication.bearer.token_parameters import TokenValidationParameters


def _get_authorization_scheme_param(authorization_header_value: str | None) -> tuple[str, str]:
    if not authorization_header_value:
        return "", ""
    scheme, _, param = authorization_header_value.partition(" ")
    return scheme, param


def _create_principal_from_jwt(token: JWTSecurityToken) -> ClaimsPrincipal:
    identity = ClaimsIdentity("AuthenticationTypes.Federation")
    if token.claims:
        identity.add_claims(*token.claims)
    return ClaimsPrincipal(identity)


class JWTBearerAuthenticationHandler(IAuthenticationHandler):
    __slots__ = ("_tvp", "_logger",)

    def __init__(self, validation_parameters: TokenValidationParameters) -> None:
        self._tvp = validation_parameters
        self._logger = logging.getLogger(self.__class__.__name__)

    async def authenticate(self, context: HttpContext, scheme: str) -> AuthenticationResult:
        authorization = context.request.headers.get("Authorization")
        scheme, token = _get_authorization_scheme_param(authorization)

        if not authorization or scheme.lower() != "bearer":
            self._logger.info("Invalid Authorization header: Bearer.")
            return AuthenticationResult(ClaimsPrincipal(), {})

        try:
            jwt_token = JWTSecurityToken.decode(
                token,
                key=self._tvp.issuer_signing_key,
                algorithms=self._tvp.valid_algorithms,
                audience=self._tvp.valid_audiences,
                issuer=self._tvp.valid_issuers,
                options=self._tvp.options,
                leeway=self._tvp.leeway
            )
            return AuthenticationResult(_create_principal_from_jwt(jwt_token), {})
        except PyJWTError as ex:
            self._logger.error(str(ex))
            return AuthenticationResult(ClaimsPrincipal(), {})

    async def sign_in(self, context: HttpContext, scheme: str, principal: ClaimsPrincipal, **properties) -> None:
        pass

    async def sign_out(self, context: HttpContext, scheme: str) -> None:
        pass
