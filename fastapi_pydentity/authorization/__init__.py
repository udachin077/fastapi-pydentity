from fastapi_pydentity.authorization.dependency import (
    IAuthorizationOptionsAccessorDepends,
    IAuthorizationPolicyProviderDepends,
    AuthorizationHandlerContextDepends,
    AuthorizationOptionsAccessor,
    AuthorizationHandlerContext,
)
from fastapi_pydentity.authorization.params import Authorize, add_authorization, use_authorization
