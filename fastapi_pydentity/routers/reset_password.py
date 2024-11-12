import logging
from collections.abc import Awaitable
from typing import Callable, Annotated

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel, SecretStr, EmailStr, model_validator
from pydentity import UserManager as _UserManager
from pydentity.types import TUser
from starlette import status

from fastapi_pydentity import UserManager
from fastapi_pydentity.routers.base import BodyType
from fastapi_pydentity.routers.utils import http_exception_openapi_scheme

logger = logging.getLogger('Authentication')


class ResetPasswordModel(BaseModel):
    token: str
    email: EmailStr
    password: SecretStr
    confirm_password: SecretStr

    @model_validator(mode='after')
    def check_passwords_match(self) -> 'ResetPasswordModel':
        password = self.password.get_secret_value()
        confirm_password = self.confirm_password.get_secret_value()
        if password is not None and confirm_password is not None and password != confirm_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=['Passwords do not match.']
            )
        return self


class ResetPasswordResponse(BaseModel):
    status_message: str = 'Your password has been reset.'


def get_reset_password_router(
        forgot_password_callback: Callable[[Request, TUser | None, _UserManager[TUser]], Awaitable[None]],
        body_type: BodyType = BodyType.FormData,
        reset_password_callback: Callable[[Request, TUser, _UserManager[TUser]], Awaitable[None]] | None = None,
) -> APIRouter:
    """

    ## Example

    ```python
    from fastapi import FastAPI

    async def forgot_password_callback(request, user, user_manager, background_tasks):
        user_id = await user_manager.get_user_id(user)
        code = await user_manager.generate_password_reset_token(user)
        callback_url = request.url_for('account:reset-password').include_query_params(code=code, userId=user_id)
        email_sender.send_email(
            email,
            'Reset password',
            f'Please <a href="{callback_url}">clicking here</a> to reset your password.'
        )


    app = FastAPI()

    app.include_router(get_reset_password_router(forgot_password_callback))
    ```

    :param forgot_password_callback: A function called for forgot password. It is used to generate a password reset code and send it to the user.
    :param body_type: Response body.
    :param reset_password_callback: A function called after reset password.
    :return:
    """
    if forgot_password_callback is None:
        raise ValueError('`forgot_password_callback` must not be None')

    router = APIRouter()

    @router.post(
        '/forgot-password',
        name='account:forgot-password',
        status_code=status.HTTP_200_OK,
        summary='Forgot your password',
    )
    async def forgot_password(
            request: Request,
            user_manager: UserManager,
            email: Annotated[EmailStr, body_type()]
    ):
        """
        Forgot your password? Enter the email address to reset the password.

        - **email**: Email address of the user to reset their password.
        """
        user = await user_manager.find_by_email(email)
        await forgot_password_callback(request, user, user_manager)

    @router.post(
        '/reset-password',
        name='account:reset-password',
        response_model=ResetPasswordResponse,
        response_model_exclude_none=True,
        responses={
            status.HTTP_200_OK: {'model': ResetPasswordResponse},
            status.HTTP_400_BAD_REQUEST: http_exception_openapi_scheme(
                'Reset Password Error', [
                    'Passwords do not match.',
                    'string',
                ]
            )
        },
        summary='Reset your password',
    )
    async def reset_password(
            request: Request,
            user_manager: UserManager,
            input_model: Annotated[ResetPasswordModel, body_type()]
    ):
        """
        Reset password.

        - **email**: Email address of the user to reset their password.
        - **password**: New password.
        - **confirmPassword**: Confirm password.
        """
        email = input_model.email
        user = await user_manager.find_by_email(email)

        if user is None:
            # Don't reveal that the user does not exist
            logger.debug(f'User with email {email} does not exist.')
            return ResetPasswordResponse()

        result = await user_manager.reset_password(user, input_model.token, input_model.password.get_secret_value())

        if result.succeeded:
            if reset_password_callback is not None:
                await reset_password_callback(request, user, user_manager)

            return ResetPasswordResponse()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=tuple(err.description for err in result.errors)
        )

    return router
