from typing import Annotated

from fastapi import Depends
from fastapi.requests import Request
from pydentity.authorization import (
    AuthorizationOptions,
    AuthorizationHandlerContext as _AuthorizationHandlerContext,
    AuthorizationPolicyProvider,
)
from pydentity.authorization.interfaces import IAuthorizationOptionsAccessor, IAuthorizationPolicyProvider

from fastapi_pydentity.authorization.options import AUTHORIZATION_OPTIONS


class AuthorizationOptionsAccessor(IAuthorizationOptionsAccessor):
    def __init__(self, o: Annotated[AuthorizationOptions, Depends(lambda: AUTHORIZATION_OPTIONS)]):
        super().__init__(o)


IAuthorizationOptionsAccessorDepends = Annotated[
    IAuthorizationOptionsAccessor, Depends(AuthorizationOptionsAccessor)
]


class AuthorizationHandlerContext(_AuthorizationHandlerContext):
    def __init__(self, request: Request):
        super().__init__(request)


AuthorizationHandlerContextDepends = Annotated[
    _AuthorizationHandlerContext, Depends(AuthorizationHandlerContext)
]


def get_authorization_policy_provider(o: IAuthorizationOptionsAccessorDepends):
    return AuthorizationPolicyProvider(o)


IAuthorizationPolicyProviderDepends = Annotated[
    IAuthorizationPolicyProvider, Depends(get_authorization_policy_provider)
]
