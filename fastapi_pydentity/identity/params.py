from collections.abc import Callable

from pydentity import IdentityOptions, IdentityErrorDescriber, UpperLookupNormalizer, DefaultUserConfirmation
from pydentity.hashers import Argon2PasswordHasher
from pydentity.interfaces.stores import IUserStore, IRoleStore
from pydentity.types import TUser, TRole
from pydentity.validators import PasswordValidator, UserValidator, RoleValidator

from fastapi_pydentity.authentication import add_authentication
from fastapi_pydentity.identity.dependency import (
    get_user_claim_principal_factory,
    get_user_manager,
    get_role_manager,
    get_signin_manager,
)
from fastapi_pydentity.identity.builder import IdentityBuilder
from fastapi_pydentity.types import DependencyCallable


def add_identity(
        get_user_store: DependencyCallable[IUserStore[TUser]],
        get_role_store: DependencyCallable[IRoleStore[TRole]],
        configure: Callable[[IdentityOptions], None] = None,
):
    add_authentication().add_identity_cookies()
    builder = IdentityBuilder()
    builder.add_user_store(get_user_store)
    builder.add_role_store(get_role_store)
    builder.add_identity_error_describer(IdentityErrorDescriber)
    builder.add_password_hasher(Argon2PasswordHasher)
    builder.add_lookup_normalizer(UpperLookupNormalizer)
    builder.add_user_confirmation(DefaultUserConfirmation)
    builder.add_user_claims_principal_factory(get_user_claim_principal_factory)
    builder.add_user_manager(get_user_manager)
    builder.add_role_manager(get_role_manager)
    builder.add_signin_manager(get_signin_manager)

    if configure:
        builder.configure_options(configure)

    return builder


def add_default_identity(
        get_user_store: DependencyCallable[IUserStore[TUser]],
        get_role_store: DependencyCallable[IRoleStore[TRole]],
        configure: Callable[[IdentityOptions], None] = None,
):
    builder = add_identity(get_user_store, get_role_store, configure)
    builder.add_password_validator(PasswordValidator)
    builder.add_user_validator(UserValidator)
    builder.add_role_validator(RoleValidator)
    builder.add_default_token_providers()
    return builder
