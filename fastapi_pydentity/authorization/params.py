from collections.abc import Iterable
from typing import Any

from fastapi import Depends
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from pydentity.authorization import (
    AuthorizationError, AuthorizationPolicy,
)
from pydentity.authorization import (
    AuthorizationHandlerContext as _AuthorizationHandlerContext,
)
from pydentity.authorization.interfaces import IAuthorizationPolicyProvider
from pydentity.exc import InvalidOperationException
from starlette.types import ExceptionHandler

from fastapi_pydentity.authorization.builder import AuthorizationBuilder
from fastapi_pydentity.authorization.dependency import (
    AuthorizationHandlerContextDepends,
    IAuthorizationPolicyProviderDepends,
)


def Authorize(roles: str | Iterable[str] | None = None, policy: str | None = None) -> Any:
    """
    Indicates that the route or router to which this dependency is applied requires the specified authorization.

    :param roles: A list of roles that are allowed to access the resource.
    :param policy: Policy name that determines access to the resource.
    :return:
    :raise InvalidOperationException: If the specified policy name is not found.
    :raise AuthorizationError: If authorization failed.
    """

    async def decorator(context: AuthorizationHandlerContextDepends, provider: IAuthorizationPolicyProviderDepends):
        await _check_policy(policy, context, provider)
        await _check_roles(roles, context)

    return Depends(decorator)


async def _check_roles(roles: str | Iterable[str] | None, context: _AuthorizationHandlerContext) -> None:
    if context.user is None:
        raise AuthorizationError()

    if roles:
        if isinstance(roles, str):
            roles = set(roles.replace(" ", "").split(","))
        else:
            roles = set(roles)

        result = any([context.user.is_in_role(r) for r in roles])

        if not result:
            raise AuthorizationError()


async def _check_policy(
        policy: str | None,
        context: _AuthorizationHandlerContext,
        provider: IAuthorizationPolicyProvider
) -> None:
    if policy:
        _policy = await provider.get_policy(policy)

        if not _policy:
            raise InvalidOperationException(f"The AuthorizationPolicy named: '{policy}' was not found.")

        for req in _policy.requirements:
            await req.handle(context)

    else:
        if default_policy := await provider.get_default_policy():
            for req in default_policy.requirements:
                await req.handle(context)

    if not context.has_succeeded:
        raise AuthorizationError()


def add_authorization(default_policy: AuthorizationPolicy | None = None):
    return AuthorizationBuilder(default_policy)


def use_authorization(app: FastAPI, on_error: ExceptionHandler | None = None):
    if on_error:
        app.add_exception_handler(AuthorizationError, on_error)
    else:
        app.add_exception_handler(
            AuthorizationError,
            lambda req, exc: PlainTextResponse("Forbidden", status_code=403)
        )
