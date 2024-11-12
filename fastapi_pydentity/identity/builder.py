from collections.abc import Callable

from pydentity import (
    UserManager,
    RoleManager,
    SignInManager,
    IdentityErrorDescriber,
    IdentityOptions,
)
from pydentity.interfaces import (
    IUserClaimsPrincipalFactory,
    IUserValidator,
    IPasswordHasher,
    IPasswordValidator,
    IRoleValidator,
    IUserConfirmation,
    ILookupNormalizer,
    IUserTwoFactorTokenProvider,
    ILogger,
)
from pydentity.interfaces.stores import IUserStore, IRoleStore
from pydentity.token_providers import (
    DataProtectorTokenProvider,
    EmailTokenProvider,
    PhoneNumberTokenProvider,
    AuthenticatorTokenProvider,
)
from pydentity.types import TUser, TRole

from fastapi_pydentity.identity.options import IDENTITY_OPTIONS
from fastapi_pydentity.identity._proxy_types import ProxyTypes
from fastapi_pydentity.types import DependencyCallable


class IdentityBuilder:
    def add_user_validator(self, validator: type[IUserValidator[TUser]]):
        ProxyTypes.UserValidatorCollection.add(validator)
        return self

    def add_password_hasher(self, hasher: DependencyCallable[IPasswordHasher[TUser]]):
        ProxyTypes.PasswordHasher.set_factory(hasher)
        return self

    def add_user_claims_principal_factory(self, factory: DependencyCallable[IUserClaimsPrincipalFactory[TUser]]):
        ProxyTypes.UserClaimsPrincipalFactory.set_factory(factory)
        return self

    def add_identity_error_describer(self, error_describer: DependencyCallable[IdentityErrorDescriber]):
        ProxyTypes.IdentityErrorDescriber.set_factory(error_describer)
        return self

    def add_password_validator(self, validator: type[IPasswordValidator[TUser]]):
        ProxyTypes.PasswordValidatorCollection.add(validator)
        return self

    def add_user_store(self, store: DependencyCallable[IUserStore[TUser]]):
        ProxyTypes.UserStore.set_factory(store)
        return self

    def add_user_manager(self, manager: DependencyCallable[UserManager[TUser]]):
        ProxyTypes.UserManager.set_factory(manager)
        return self

    def add_role_validator(self, validator: type[IRoleValidator[TUser]]):
        ProxyTypes.RoleValidatorCollection.add(validator)
        return self

    def add_role_store(self, store: DependencyCallable[IRoleStore[TUser]]):
        ProxyTypes.RoleStore.set_factory(store)
        return self

    def add_role_manager(self, manager: DependencyCallable[RoleManager[TRole]]):
        ProxyTypes.RoleManager.set_factory(manager)
        return self

    def add_user_confirmation(self, confirmation: DependencyCallable[IUserConfirmation[TUser]]):
        ProxyTypes.UserConfirmation.set_factory(confirmation)
        return self

    def add_lookup_normalizer(self, lookup_normalizer: DependencyCallable[ILookupNormalizer]):
        ProxyTypes.LookupNormalizer.set_factory(lookup_normalizer)
        return self

    def add_token_provider(self, provider_name: str, provider: IUserTwoFactorTokenProvider[TUser]):
        IDENTITY_OPTIONS.tokens.provider_map[provider_name] = provider
        return self

    def add_default_token_providers(self):
        self.add_token_provider(IDENTITY_OPTIONS.tokens.DEFAULT_PROVIDER, DataProtectorTokenProvider())
        self.add_token_provider(IDENTITY_OPTIONS.tokens.DEFAULT_EMAIL_PROVIDER, EmailTokenProvider())
        self.add_token_provider(IDENTITY_OPTIONS.tokens.DEFAULT_PHONE_PROVIDER, PhoneNumberTokenProvider())
        self.add_token_provider(IDENTITY_OPTIONS.tokens.DEFAULT_AUTHENTICATION_PROVIDER, AuthenticatorTokenProvider())
        return self

    def add_signin_manager(self, manager: DependencyCallable[SignInManager[TUser]]):
        ProxyTypes.SignInManager.set_factory(manager)
        return self

    def add_user_manager_logger(self, logger: DependencyCallable[ILogger[UserManager[TUser]]]):
        ProxyTypes.LoggerUserManager.set_factory(logger)
        return self

    def add_role_manager_logger(self, logger: DependencyCallable[ILogger[RoleManager[TRole]]]):
        ProxyTypes.LoggerRoleManager.set_factory(logger)
        return self

    def add_signin_manager_logger(self, logger: DependencyCallable[ILogger[SignInManager[TUser]]]):
        ProxyTypes.LoggerSignInManager.set_factory(logger)
        return self

    def configure_options(self, action: Callable[[IdentityOptions], None]):
        action(IDENTITY_OPTIONS)
