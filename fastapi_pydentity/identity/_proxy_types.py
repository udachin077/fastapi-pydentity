from typing import Annotated

from fastapi.params import Depends
from pydentity import IdentityErrorDescriber

_ReturnNone = lambda: None


class _Depends:
    __slots__ = ("__call__",)

    def __init__(self, factory=None):
        self.__call__ = factory or _ReturnNone

    def set_factory(self, factory):
        self.__call__ = factory
        return self


class ProxyTypes:
    IdentityErrorDescriber = _Depends()
    UserStore = _Depends()
    RoleStore = _Depends()
    PasswordHasher = _Depends()
    LookupNormalizer = _Depends()
    UserConfirmation = _Depends()
    UserClaimsPrincipalFactory = _Depends()
    UserManager = _Depends()
    RoleManager = _Depends()
    SignInManager = _Depends()
    LoggerUserManager = _Depends()
    LoggerRoleManager = _Depends()
    LoggerSignInManager = _Depends()
    PasswordValidatorCollection = None
    UserValidatorCollection = None
    RoleValidatorCollection = None


class ValidatorCollection:
    def __init__(self):
        self.__validators = []

    def add(self, validator):
        self.__validators.append(validator)
        return self

    def __call__(self, errors: Annotated[IdentityErrorDescriber, Depends(ProxyTypes.IdentityErrorDescriber)]):
        return tuple(v(errors) for v in self.__validators)


ProxyTypes.PasswordValidatorCollection = ValidatorCollection()
ProxyTypes.UserValidatorCollection = ValidatorCollection()
ProxyTypes.RoleValidatorCollection = ValidatorCollection()
