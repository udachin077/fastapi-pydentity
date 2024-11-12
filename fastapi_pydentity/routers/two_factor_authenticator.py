import logging
from collections.abc import Awaitable
from typing import Annotated, Iterable, Any, Callable

from fastapi import APIRouter, Request, HTTPException
from pydantic import AfterValidator, BeforeValidator
from pydentity import UserManager as _UserManager
from pydentity.types import TUser
from starlette import status

from fastapi_pydentity import Authorize, UserManager, SignInManager
from fastapi_pydentity.routers.base import BaseModel, BodyType
from fastapi_pydentity.routers.utils import http_exception_openapi_scheme

logger = logging.getLogger("Account:Authenticator")

HTTP_404_NOT_FOUND_SCHEME = http_exception_openapi_scheme('Not Found', 'User not found.')


async def _get_current_user(request: Request, user_manager: _UserManager[TUser]) -> TUser:
    # Need to use middleware for access to request.user
    user = await user_manager.get_user(request.user)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unable to load user with ID '{await user_manager.get_user_id(request.user)}'."
        )

    return user


class EnabledAuthenticatorModel(BaseModel):
    two_factor_code: Annotated[str, AfterValidator(lambda v: v.replace(" ", "").replace("-", ""))]
    generate_recovery_codes: Annotated[bool, BeforeValidator(lambda v: False if v == '' else v)] = False


class AuthenticatorResponse(BaseModel):
    authenticator_uri: str
    shared_key: str


class RecoveryCodesResponse(BaseModel):
    recovery_codes: Iterable[str] | None = None


class EnabledAuthenticatorResponse(RecoveryCodesResponse):
    pass


def get_two_factor_authenticator_router(
        title: str,
        body_type: BodyType = BodyType.FormData,
        get_authenticator_username: Callable[[TUser, _UserManager[TUser]], Awaitable[str]] | None = None,
        digits: int = 6,
        digest: Any = None,
        interval: int = 30,
        image: str | None = None,
        recovery_codes_count: int = 10,
) -> APIRouter:
    """

    ## Example

    ```python
    from fastapi import FastAPI

    app = FastAPI()

    app.include_router(get_two_factor_authenticator_router('PydentityApp'))
    ```

    :param title: Application name.
    :param body_type: Response body.
    :param get_authenticator_username: Name of the account generator.
    :param digits: Number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
    :param digest: Digest function to use in the HMAC (expected to be SHA1).
    :param interval: The time interval in seconds for OTP. This defaults to 30.
    :param image: Optional logo image URL.
    :param recovery_codes_count: The number of recovery codes to generate.
    :return:
    """
    if not title:
        raise ValueError("Title cannot be empty.")

    router = APIRouter(dependencies=[Authorize()])

    @router.get(
        '/enable-authenticator',
        name='account:enable-authenticator',
        status_code=status.HTTP_200_OK,
        response_model=AuthenticatorResponse,
        responses={
            status.HTTP_200_OK: {'model': AuthenticatorResponse},
            status.HTTP_404_NOT_FOUND: HTTP_404_NOT_FOUND_SCHEME
        },
        summary='Enable authenticator',
    )
    async def enable_authenticator(request: Request, user_manager: UserManager):
        """Returns URI for generate QR code and key for manual enter."""
        user = await _get_current_user(request, user_manager)
        authenticator_uri, shared_key = await _load_shared_key_and_qrcode_uri(user, user_manager)
        return AuthenticatorResponse(authenticator_uri=authenticator_uri, shared_key=shared_key)

    @router.post(
        '/enable-authenticator',
        name='account:enable-authenticator',
        status_code=status.HTTP_200_OK,
        response_model=EnabledAuthenticatorResponse,
        response_model_exclude_none=True,
        responses={
            status.HTTP_200_OK: {'model': EnabledAuthenticatorResponse},
            status.HTTP_400_BAD_REQUEST: http_exception_openapi_scheme(
                'Enable Authenticator Error',
                'Verification code is invalid.'
            ),
            status.HTTP_404_NOT_FOUND: HTTP_404_NOT_FOUND_SCHEME
        },
        summary='Enable authenticator',
    )
    async def enable_authenticator(
            request: Request,
            user_manager: UserManager,
            input_model: Annotated[EnabledAuthenticatorModel, body_type()]
    ):
        """
        Turn on the authenticator after checking the two-factor code.

        - **twoFactorCode**: Two-factor code.
        - **generateRecoveryCodes**: Specifies whether recovery codes should be generated and returned.
        """
        user = await _get_current_user(request, user_manager)
        is_2fa_token_valid = await user_manager.verify_two_factor_token(
            user,
            user_manager.options.tokens.authenticator_token_provider,
            input_model.two_factor_code
        )

        if not is_2fa_token_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Verification code is invalid.'
            )

        enabled_2fa_result = await user_manager.set_two_factor_enabled(user, True)

        if not enabled_2fa_result.succeeded:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail='Unexpected error occurred enabling 2FA.'
            )

        logger.info(f"User with ID '{await user_manager.get_user_id(user)}' has enabled 2FA with an authenticator app.")

        if (
                input_model.generate_recovery_codes and
                recovery_codes_count > 0 and
                await user_manager.count_recovery_codes(user) == 0
        ):
            recovery_codes = await user_manager.generate_new_two_factor_recovery_codes(user, recovery_codes_count)
            return EnabledAuthenticatorResponse(recovery_codes=recovery_codes)
        else:
            return EnabledAuthenticatorResponse()

    async def _load_shared_key_and_qrcode_uri(user: TUser, user_manager: _UserManager[TUser]):
        key = await user_manager.get_authenticator_key(user)

        if not key:
            await user_manager.reset_authenticator_key(user)
            key = await user_manager.get_authenticator_key(user)

        shared_key = " ".join(key[i:i + 4] for i in range(0, len(key), 4))

        name = (
            await get_authenticator_username(user, user_manager)
            if get_authenticator_username is not None
            else None
        )

        authenticator_uri = await user_manager.get_authenticator_provisioning_uri(
            user,
            name=name,
            title=title,
            digits=digits,
            digest=digest,
            interval=interval,
            image=image
        )
        return authenticator_uri, shared_key

    @router.get(
        '/generate-recovery-codes',
        name='account:generate-recovery-codes',
        status_code=status.HTTP_200_OK,
        response_model=RecoveryCodesResponse,
        response_model_exclude_none=True,
        responses={
            status.HTTP_200_OK: {'model': RecoveryCodesResponse},
            status.HTTP_400_BAD_REQUEST: http_exception_openapi_scheme(
                'Generate Recovery Codes Error',
                'Cannot generate recovery codes for user because they do not have 2FA enabled.'
            ),
            status.HTTP_404_NOT_FOUND: HTTP_404_NOT_FOUND_SCHEME
        },
        summary='Generate recovery codes',
    )
    async def generate_recovery_codes(request: Request, user_manager: UserManager):
        """Generate recovery codes for current user."""
        user = await _get_current_user(request, user_manager)
        is_two_factor_enabled = await user_manager.get_two_factor_enabled(user)

        if not is_two_factor_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Cannot generate recovery codes for user because they do not have 2FA enabled.'
            )

        recovery_codes = await user_manager.generate_new_two_factor_recovery_codes(user, recovery_codes_count)
        return RecoveryCodesResponse(recovery_codes=recovery_codes)

    @router.post(
        '/disable-authenticator',
        name='account.manage:disable-authenticator',
        status_code=status.HTTP_200_OK,
        responses={
            status.HTTP_404_NOT_FOUND: HTTP_404_NOT_FOUND_SCHEME
        },
        summary='Disable authenticator',
    )
    async def disable_authenticator(request: Request, user_manager: UserManager):
        """Disable authenticator for current user."""
        user = await _get_current_user(request, user_manager)
        disable_2fa_result = await user_manager.set_two_factor_enabled(user, False)

        if not disable_2fa_result.succeeded:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail='Unexpected error occurred disabling 2FA.'
            )

        logger.info(f"User with ID '{await user_manager.get_user_id(user)}' has disabled 2fa.")

    @router.post(
        '/reset-authenticator',
        name='account.manage:reset-authenticator',
        status_code=status.HTTP_200_OK,
        responses={
            status.HTTP_404_NOT_FOUND: HTTP_404_NOT_FOUND_SCHEME
        },
        summary='Reset authenticator',
    )
    async def reset_authenticator(
            request: Request,
            user_manager: UserManager,
            signin_manager: SignInManager
    ):
        """Reset authenticator for current user."""
        await disable_authenticator(request, user_manager)
        user = await user_manager.get_user(request.user)
        reset_authenticator_key_result = await user_manager.reset_authenticator_key(user)

        if not reset_authenticator_key_result.succeeded:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail='Unexpected error occurred reset authenticator 2FA.'
            )

        logger.info(f"User with ID '{await user_manager.get_user_id(user)}' has reset their authentication app key.")
        await signin_manager.refresh_sign_in(user)

    return router
