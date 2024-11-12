from typing import Annotated

from fastapi import Depends
from pydentity.authentication import AuthenticationOptions, AuthenticationSchemeProvider
from pydentity.authentication.interfaces import IAuthenticationOptionsAccessor, IAuthenticationSchemeProvider

from fastapi_pydentity.authentication.options import AUTHENTICATION_OPTIONS


class AuthenticationOptionsAccessor(IAuthenticationOptionsAccessor):
    def __init__(self, o: Annotated[AuthenticationOptions, Depends(lambda: AUTHENTICATION_OPTIONS)]):
        super().__init__(o)


IAuthenticationOptionsAccessorDepends = Annotated[
    IAuthenticationOptionsAccessor, Depends(AuthenticationOptionsAccessor)
]


def get_authentication_scheme_provider(o: IAuthenticationOptionsAccessorDepends):
    return AuthenticationSchemeProvider(o)


IAuthenticationSchemeProviderDepends = Annotated[
    IAuthenticationSchemeProvider, Depends(get_authentication_scheme_provider)
]
