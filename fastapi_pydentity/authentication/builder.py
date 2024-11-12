from datetime import timedelta
from typing import overload, Callable

from pydentity import IdentityConstants
from pydentity.authentication import AuthenticationScheme, AuthenticationSchemeBuilder

from fastapi_pydentity.authentication.options import AUTHENTICATION_OPTIONS
from fastapi_pydentity.authentication.bearer import (
    TokenValidationParameters,
    JWTBearerAuthenticationHandler,
)
from fastapi_pydentity.authentication.cookie import (
    CookieAuthenticationOptions,
    CookieAuthenticationHandler,
)


class AuthenticationBuilder:
    """Used to configure authentication."""

    __slots__ = ()

    def __init__(self, default_scheme: str | None = None):
        if default_scheme:
            AUTHENTICATION_OPTIONS.default_scheme = default_scheme

    @overload
    def add_scheme(self, name: str, scheme: AuthenticationScheme) -> "AuthenticationBuilder":
        """
        Adds a ``AuthenticationScheme``.

        :param name: The name of this scheme.
        :param scheme:
        :return:
        """

    @overload
    def add_scheme(
            self,
            name: str,
            configure_scheme: Callable[[AuthenticationSchemeBuilder], None]
    ) -> "AuthenticationBuilder":
        """
        Adds a ``AuthenticationScheme``.

        :param name: The name of this scheme.
        :param configure_scheme:
        :return:
        """

    def add_scheme(
            self,
            name: str,
            scheme_or_builder: AuthenticationScheme | Callable[[AuthenticationSchemeBuilder], None],
    ) -> "AuthenticationBuilder":
        AUTHENTICATION_OPTIONS.add_scheme(name, scheme_or_builder)
        return self

    def add_cookie(
            self,
            scheme: str = "Cookie",
            cookie_options: CookieAuthenticationOptions | None = None
    ) -> "AuthenticationBuilder":
        """
        Adds cookie authentication to ``AuthenticationBuilder`` using the specified scheme.

        :param scheme: The authentication scheme.
        :param cookie_options:
        :return:
        """
        return self.add_scheme(scheme, AuthenticationScheme(scheme, CookieAuthenticationHandler(cookie_options)))

    def add_identity_cookies(self) -> "AuthenticationBuilder":
        self.add_cookie(IdentityConstants.ApplicationScheme)
        self.add_cookie(IdentityConstants.ExternalScheme, CookieAuthenticationOptions(timespan=timedelta(minutes=10)))
        self.add_cookie(IdentityConstants.TwoFactorRememberMeScheme)
        self.add_cookie(IdentityConstants.TwoFactorUserIdScheme)
        return self

    def add_jwt_bearer(
            self,
            scheme: str = "Bearer",
            *,
            validation_parameters: TokenValidationParameters
    ) -> "AuthenticationBuilder":
        """
        Enables JWT-bearer authentication using the default scheme 'Bearer'.

        :param scheme: The authentication scheme.
        :param validation_parameters:
        :return:
        """
        self.add_scheme(scheme, AuthenticationScheme(scheme, JWTBearerAuthenticationHandler(validation_parameters)))
        return self
