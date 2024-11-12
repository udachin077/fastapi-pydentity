from typing import Annotated

from fastapi import Depends
from pydentity import (
    IdentityErrorDescriber,
    IdentityOptions,
    UserManager,
    RoleManager,
    SignInManager, UserClaimsPrincipalFactory,
)
from pydentity.interfaces import (
    IPasswordHasher,
    ILookupNormalizer,
    IUserConfirmation,
    IPasswordValidator,
    IUserValidator,
    IRoleValidator,
    IUserClaimsPrincipalFactory,
    ILogger,
)
from pydentity.interfaces.stores import IUserStore, IRoleStore

from fastapi_pydentity.authentication.dependency import IAuthenticationSchemeProviderDepends
from fastapi_pydentity.http._dependency import IHttpContextAccessorDepends
from fastapi_pydentity.identity.options import IDENTITY_OPTIONS
from fastapi_pydentity.identity._proxy_types import ProxyTypes

IdentityErrorDescriberDepends = Annotated[IdentityErrorDescriber, Depends(ProxyTypes.IdentityErrorDescriber)]
LoggerUserManagerDepends = Annotated[ILogger, Depends(ProxyTypes.LoggerUserManager)]
LoggerRoleManagerDepends = Annotated[ILogger, Depends(ProxyTypes.LoggerRoleManager)]
LoggerSignInManagerDepends = Annotated[ILogger, Depends(ProxyTypes.LoggerSignInManager)]
IdentityOptionsDepends = Annotated[IdentityOptions, Depends(lambda: IDENTITY_OPTIONS)]
UserStoreDepends = Annotated[IUserStore, Depends(ProxyTypes.UserStore)]
RoleStoreDepends = Annotated[IRoleStore, Depends(ProxyTypes.RoleStore)]
PasswordHasherDepends = Annotated[IPasswordHasher, Depends(ProxyTypes.PasswordHasher)]
LookupNormalizerDepends = Annotated[ILookupNormalizer, Depends(ProxyTypes.LookupNormalizer)]
UserConfirmationDepends = Annotated[IUserConfirmation, Depends(ProxyTypes.UserConfirmation)]
PasswordValidatorDepends = Annotated[tuple[IPasswordValidator], Depends(ProxyTypes.PasswordValidatorCollection)]
UserValidatorDepends = Annotated[tuple[IUserValidator], Depends(ProxyTypes.UserValidatorCollection)]
RoleValidatorDepends = Annotated[tuple[IRoleValidator], Depends(ProxyTypes.RoleValidatorCollection)]
UserManagerDepends = Annotated[UserManager, Depends(ProxyTypes.UserManager)]
RoleManagerDepends = Annotated[RoleManager, Depends(ProxyTypes.RoleManager)]
UserClaimsPrincipalFactoryDepends = Annotated[
    IUserClaimsPrincipalFactory, Depends(ProxyTypes.UserClaimsPrincipalFactory)
]
SignInManagerDepends = Annotated[SignInManager, Depends(ProxyTypes.SignInManager)]


def get_user_manager(
        store: UserStoreDepends,
        password_hasher: PasswordHasherDepends,
        password_validators: PasswordValidatorDepends,
        user_validators: UserValidatorDepends,
        key_normalizer: LookupNormalizerDepends,
        errors: IdentityErrorDescriberDepends,
        logger: LoggerUserManagerDepends,
        options: IdentityOptionsDepends
) -> UserManager:
    return UserManager(
        store=store,
        options=options,
        password_hasher=password_hasher,
        password_validators=password_validators,
        user_validators=user_validators,
        key_normalizer=key_normalizer,
        errors=errors,
        logger=logger
    )


def get_role_manager(
        store: RoleStoreDepends,
        role_validators: RoleValidatorDepends,
        key_normalizer: LookupNormalizerDepends,
        errors: IdentityErrorDescriberDepends,
        logger: LoggerRoleManagerDepends
) -> RoleManager:
    return RoleManager(
        store=store,
        role_validators=role_validators,
        key_normalizer=key_normalizer,
        errors=errors,
        logger=logger
    )


def get_user_claim_principal_factory(
        user_manager: UserManagerDepends,
        role_manager: RoleManagerDepends,
        options: IdentityOptionsDepends
) -> IUserClaimsPrincipalFactory:
    return UserClaimsPrincipalFactory(user_manager=user_manager, role_manager=role_manager, options=options)


def get_signin_manager(
        user_manager: UserManagerDepends,
        context_accessor: IHttpContextAccessorDepends,
        schemes: IAuthenticationSchemeProviderDepends,
        claims_factory: UserClaimsPrincipalFactoryDepends,
        confirmation: UserConfirmationDepends,
        logger: LoggerSignInManagerDepends,
        options: IdentityOptionsDepends
) -> SignInManager:
    return SignInManager(
        user_manager=user_manager,
        context_accessor=context_accessor,
        schemes=schemes,
        claims_factory=claims_factory,
        confirmation=confirmation,
        options=options,
        logger=logger
    )
