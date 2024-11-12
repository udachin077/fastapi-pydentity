from collections.abc import Awaitable
from typing import Annotated, Callable

from fastapi import APIRouter, Request, HTTPException
from pydantic import SecretStr, model_validator
from pydentity import UserManager as _UserManager
from pydentity.types import TUser
from starlette import status

from fastapi_pydentity import UserManager, SignInManager
from fastapi_pydentity.routers.base import BaseModel, BodyType


class ChangePasswordModel(BaseModel):
    current_password: SecretStr
    new_password: SecretStr
    confirm_password: SecretStr

    @model_validator(mode='after')
    def check_passwords_match(self) -> 'ChangePasswordModel':
        if self.current_password is not None and self.new_password is not None and self.current_password == self.new_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=['The current and new passwords match.']
            )

        if self.new_password is not None and self.confirm_password is not None and self.new_password != self.confirm_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=['Passwords do not match.']
            )

        return self


def get_change_password_router(
        body_type: BodyType = BodyType.FormData,
        change_password_callback: Callable[[Request, TUser, _UserManager[TUser]], Awaitable[None]] | None = None,
) -> APIRouter:
    """

    ## Example

    ```python
    from fastapi import FastAPI

    app = FastAPI()

    app.include_router(get_change_password_router())
    ```

    :param body_type: Response body.
    :param change_password_callback: A function called after change password.
    :return:
    """
    router = APIRouter()

    @router.post(
        '/change-password',
        name='account:change-password',
        status_code=status.HTTP_200_OK,
        summary='Change password'
    )
    async def change_password(
            request: Request,
            signin_manager: SignInManager,
            user_manager: UserManager,
            input_model: Annotated[ChangePasswordModel, body_type()]
    ):
        """
        Change password for active user.

        - **currentPassword**: Current password.
        - **newPassword**: New password.
        - **confirmPassword**: Confirm new password.
        """
        # Need to use middleware for access to request.user
        user = await user_manager.get_user(request.user)

        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Unable to load user with ID '{await user_manager.get_user_id(request.user)}'."
            )

        change_password_result = await user_manager.change_password(
            user,
            input_model.current_password.get_secret_value(),
            input_model.new_password.get_secret_value()
        )

        if not change_password_result.succeeded:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=tuple(e.description for e in change_password_result.errors)
            )

        if change_password_callback is not None:
            await change_password_callback(request, user, user_manager)

        await signin_manager.refresh_sign_in(user)

    return router
