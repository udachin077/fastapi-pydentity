import logging
from dataclasses import dataclass
from typing import Callable, Annotated, Awaitable

import email_validator
from fastapi import APIRouter, HTTPException, Request
from pydantic import SecretStr, BeforeValidator, AfterValidator
from pydentity import SignInManager as _SignInManager
from pydentity.types import TUser
from starlette import status

from fastapi_pydentity import Authorize, SignInManager
from fastapi_pydentity.routers.base import BaseModel, BodyType
from fastapi_pydentity.routers.utils import http_exception_openapi_scheme

logger = logging.getLogger("Authentication")


@dataclass
class Tokens:
    access_token: str | None = None
    refresh_token: str | None = None


_GenerateAccessToken = Callable[[TUser, _SignInManager[TUser]], Awaitable[str]]
_GenerateRefreshToken = Callable[[TUser, _SignInManager[TUser]], Awaitable[str]]
_LoginCallback = Callable[[Request, TUser, _SignInManager[TUser], Tokens], Awaitable[None]]
_LogoutCallback = Callable[[Request, _SignInManager[TUser]], Awaitable[None]]


class LoginModel(BaseModel):
    username: str
    password: SecretStr
    remember_me: Annotated[bool, BeforeValidator(lambda v: True if v else False)] = False


class TwoFactorLoginModel(BaseModel):
    two_factor_code: Annotated[str, AfterValidator(lambda v: v.replace(" ", "").replace("-", ""))]
    remember_me: bool = False
    remember_machine: bool = False


class RecoveryCodeLoginModel(BaseModel):
    recovery_code: Annotated[str, AfterValidator(lambda v: v.replace(" ", ""))]


class LoginResponse(BaseModel):
    login: bool
    two_factor_complete: bool
    access_token: str | None = None
    refresh_token: str | None = None


def LoginCompleteResponse(access_token: str | None = None, refresh_token: str | None = None):  # noqa: N802
    return LoginResponse(login=True, two_factor_complete=True, access_token=access_token, refresh_token=refresh_token)


def RequiresTwoFactorResponse():  # noqa: N802
    return LoginResponse(login=True, two_factor_complete=False)


def get_login_router(
        body_type: BodyType = BodyType.FormData,
        allow_login_by_username: bool = False,
        enable_2fa: bool = False,
        generate_access_token: _GenerateAccessToken | None = None,
        generate_refresh_token: _GenerateRefreshToken | None = None,
        login_callback: _LoginCallback | None = None,
        logout_callback: _LogoutCallback | None = None,
) -> APIRouter:
    """

    ## Example

    ```python
    from fastapi import FastAPI

    app = FastAPI()

    app.include_router(get_login_router(enable_2fa=True))
    ```

    :param body_type: Response body.
    :param allow_login_by_username: If ``False``, then you can only log in by email.
    :param enable_2fa: Add routes for 2FA.
    :param generate_access_token: A function for generating a access token.
    :param generate_refresh_token: A function for generating a refresh token.
    :param login_callback: The function that is called after log in.
    :param logout_callback: The function that is called after log out.
    :return:
    """
    router = APIRouter()

    @router.post(
        '/login',
        name='auth:login',
        response_model=LoginResponse,
        status_code=status.HTTP_200_OK,
        response_model_exclude_none=True,
        responses={
            status.HTTP_200_OK: {'model': LoginResponse},
            status.HTTP_401_UNAUTHORIZED: http_exception_openapi_scheme(
                'Unauthorized',
                'Invalid username and/or password.'
            ),
            status.HTTP_403_FORBIDDEN: http_exception_openapi_scheme(
                'Access Denied',
                'This account has been locked out, please try again later.'
            ),
            status.HTTP_500_INTERNAL_SERVER_ERROR: http_exception_openapi_scheme(
                'Internal Server Error',
                'Access using the username is prohibited.'
            )
        },
        summary='Login'
    )
    async def login(
            request: Request,
            signin_manager: SignInManager,
            input_model: Annotated[LoginModel, body_type()]
    ):
        """
        Login with email or username.

        - **username**: Email or username.
        - **password**: Password.
        """
        username = input_model.username
        user = None

        try:
            email_validator.validate_email(username, check_deliverability=False)
        except email_validator.EmailSyntaxError:
            if not allow_login_by_username:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail='Access using the username is prohibited.'
                )
        else:
            user_manager = signin_manager.user_manager
            user = await user_manager.find_by_email(username)

            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail='Invalid username and/or password.'
                )

            username = await user_manager.get_username(user)

        result = await signin_manager.password_sign_in(
            username=username,
            password=input_model.password.get_secret_value(),
            is_persistent=input_model.remember_me
        )

        if result.succeeded:
            if user is None:
                user = await signin_manager.user_manager.find_by_name(username)

            return await get_login_response(request, user, signin_manager)

        if result.requires_two_factor:
            return RequiresTwoFactorResponse()

        user_manager = signin_manager.user_manager
        user = await user_manager.find_by_name(username)
        user_id = await user_manager.get_user_id(user)

        if result.is_locked_out:
            logger.warning(f'User account locked out for user with ID {user_id}.')
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail='This account has been locked out, please try again later.'
            )

        logger.warning(f"{result} for user with ID {user_id}.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid username and/or password.'
        )

    @router.post(
        '/logout',
        name='auth:logout',
        status_code=status.HTTP_200_OK,
        dependencies=[Authorize()],
        responses={
            status.HTTP_403_FORBIDDEN: http_exception_openapi_scheme(
                'Access Denied',
                'The user is not logged in.'
            )
        },
        summary='Logout'
    )
    async def logout(request: Request, signin_manager: SignInManager):
        """Logout for current user."""
        if logout_callback is not None:
            await logout_callback(request, signin_manager)

        await signin_manager.sign_out()

    async def get_login_response(
            request: Request,
            user: TUser,
            signin_manager: _SignInManager[TUser]
    ):
        access_token, refresh_token = None, None

        if generate_access_token is not None:
            access_token = await generate_access_token(user, signin_manager)

            if generate_refresh_token is not None:
                refresh_token = await generate_refresh_token(user, signin_manager)

        if login_callback is not None:
            await login_callback(
                request,
                user,
                signin_manager,
                Tokens(access_token=access_token, refresh_token=refresh_token)
            )

        return LoginCompleteResponse(access_token=access_token, refresh_token=refresh_token)

    if enable_2fa:
        @router.post(
            '/login-with-2fa',
            name='auth:login-with-2fa',
            status_code=status.HTTP_200_OK,
            response_model=LoginResponse,
            response_model_exclude_none=True,
            responses={
                status.HTTP_200_OK: {'model': LoginResponse},
                status.HTTP_401_UNAUTHORIZED: http_exception_openapi_scheme(
                    'Unauthorized',
                    'Invalid authenticator code.'
                ),
                status.HTTP_403_FORBIDDEN: http_exception_openapi_scheme(
                    'Access Denied',
                    'This account has been locked out, please try again later.'
                )
            },
            summary='Login with 2FA'
        )
        async def login_with_2fa(
                request: Request,
                signin_manager: SignInManager,
                input_model: Annotated[TwoFactorLoginModel, body_type()]
        ):
            """
            Login with two-factor authentication.

            - **twoFactorCode**: Two-factor code from authenticator app.
            """
            user = await signin_manager.get_two_factor_authentication_user()

            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail='Unable to load two-factor authentication user.'
                )

            result = await signin_manager.two_factor_authenticator_sign_in(
                input_model.two_factor_code,
                input_model.remember_me,
                input_model.remember_machine
            )
            return await get_two_factor_response(
                result,
                request,
                user,
                signin_manager,
                'Invalid authenticator code.'
            )

        @router.post(
            '/login-with-recovery-code',
            name='auth:login-with-recovery-code',
            response_model=LoginResponse,
            status_code=status.HTTP_200_OK,
            response_model_exclude_none=True,
            responses={
                status.HTTP_200_OK: {'model': LoginResponse},
                status.HTTP_401_UNAUTHORIZED: http_exception_openapi_scheme(
                    'Unauthorized',
                    'Invalid recovery code.'
                ),
                status.HTTP_403_FORBIDDEN: http_exception_openapi_scheme(
                    'Access Denied',
                    'This account has been locked out, please try again later.'
                )
            },
            summary='Login with recovery code'
        )
        async def login_with_recovery_code(
                request: Request,
                signin_manager: SignInManager,
                input_model: Annotated[RecoveryCodeLoginModel, body_type()]
        ):
            """
            Login with recovery code.

            - **recoveryCode**: Recovery code.
            """
            user = await signin_manager.get_two_factor_authentication_user()

            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail='Unable to load two-factor authentication user.'
                )

            result = await signin_manager.two_factor_recovery_code_sign_in(input_model.recovery_code)
            return await get_two_factor_response(
                result,
                request,
                user,
                signin_manager,
                'Invalid recovery code.'
            )

        async def get_two_factor_response(
                result,
                request,
                user: TUser,
                signin_manager,
                error_message
        ):
            if result.succeeded:
                return await get_login_response(request, user, signin_manager)

            user_id = await signin_manager.user_manager.get_user_id(user)

            if result.is_locked_out:
                logger.warning(f'User account locked out for user with ID {user_id}.')
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail='This account has been locked out, please try again later.'
                )

            logger.warning(f'{result} for user with ID {user_id}.')
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=error_message
            )

    return router
