from fastapi_pydentity.authentication import add_authentication, use_authentication
from fastapi_pydentity.authorization import add_authorization, use_authorization, Authorize
from fastapi_pydentity.identity import (
    IdentityOptionsDepends as IdentityOptions,
    UserStoreDepends as UserStore,
    RoleStoreDepends as RoleStore,
    UserManagerDepends as UserManager,
    RoleManagerDepends as RoleManager,
    SignInManagerDepends as SignInManager,
    add_identity,
    add_default_identity,
)
