from typing import Annotated, Callable, Awaitable

from fastapi import APIRouter, Request, HTTPException
from pydantic import EmailStr, SecretStr, model_validator, BeforeValidator
from pydentity import UserManager as _UserManager
from pydentity.types import TUser
from starlette import status

from fastapi_pydentity import UserManager
from fastapi_pydentity.routers.base import BaseModel, BodyType
from fastapi_pydentity.routers.utils import http_exception_openapi_scheme

_RegisterCallback = Callable[[Request, TUser, _UserManager[TUser]], Awaitable[None]]


class RegisterModel(BaseModel):
    email: EmailStr
    password: SecretStr
    confirm_password: SecretStr
    username: Annotated[str | None, BeforeValidator(lambda v: v if v else None)] = None

    @model_validator(mode='after')
    def check_username(self) -> 'RegisterModel':
        self.username = self.username or self.email
        return self

    @model_validator(mode='after')
    def check_passwords_match(self) -> 'RegisterModel':
        if self.password is not None and self.confirm_password is not None and self.password != self.confirm_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=['Passwords do not match.']
            )
        return self


class RegisterResponse(BaseModel):
    email: EmailStr
    username: str
    user_id: str


def get_register_router(
        body_type: BodyType = BodyType.FormData,
        register_callback: _RegisterCallback | None = None,
):
    """

    ## Example

    ```python
    from fastapi import FastAPI

    async def register_callback(request, user, user_manager, background_tasks):
        email = await user_manager.get_email(user)
        user_id = await user_manager.get_user_id(user)
        code = await user_manager.generate_email_confirmation_token(user)
        callback_url = request.url_for('account:confirm-email').include_query_params(code=code, userId=user_id)
        email_sender.send_email(
            email,
            'Email confirmation',
            f'Please confirm your account by <a href="{callback_url}">clicking here</a>.'
        )


    app = FastAPI()

    app.include_router(get_register_router(register_callback=register_callback))
    ```

    :param body_type: Response body.
    :param register_callback: A function called after registration. It can be used, for example, to confirm email.
    :return:
    """
    router = APIRouter()

    @router.post(
        '/register',
        name='account:register',
        status_code=status.HTTP_201_CREATED,
        response_model=RegisterResponse,
        responses={
            status.HTTP_201_CREATED: {'model': RegisterResponse},
            status.HTTP_400_BAD_REQUEST: http_exception_openapi_scheme(
                'Register Error',
                [
                    'Passwords do not match.',
                    'string',
                ]
            )
        },
        summary='Register account'
    )
    async def register(
            request: Request,
            user_manager: UserManager,
            input_model: Annotated[RegisterModel, body_type()]
    ):
        """
        Register new account.

        - **email**: Email address.
        - **password**: Password.
        - **confirmPassword**: Confirm password.
        - **username**: Username. If not specified, email will be used.
        """
        user = user_manager.store.create_model_from_dict(
            email=input_model.email,
            username=input_model.username
        )
        result = await user_manager.create(user, input_model.password.get_secret_value())

        if not result.succeeded:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=tuple(err.description for err in result.errors)
            )

        if register_callback is not None:
            await register_callback(request, user, user_manager)

        return RegisterResponse(
            email=input_model.email,
            username=input_model.username,
            user_id=await user_manager.get_user_id(user)
        )

    return router
