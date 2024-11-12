import json
from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Response, Request
from pydantic import SecretStr
from starlette import status

from fastapi_pydentity import UserManager, SignInManager, Authorize
from fastapi_pydentity.routers.base import BodyType
from fastapi_pydentity.routers.utils import http_exception_openapi_scheme


def get_download_personal_data_router() -> APIRouter:
    """

    ## Example

    ```python
    from fastapi import FastAPI

    app = FastAPI()

    app.include_router(get_download_personal_data_router())
    ```

    :return:
    """
    router = APIRouter()

    @router.post(
        '/download-personal-data',
        name='account:download-personal-data',
        status_code=status.HTTP_200_OK,
        dependencies=[Authorize()],
        responses={
            status.HTTP_404_NOT_FOUND: http_exception_openapi_scheme(
                'Not Found',
                'User not found.'
            )
        },
        summary='Download personal data',
    )
    async def download_personal_data(request: Request, user_manager: UserManager):
        """Download personal data for current user."""
        # Need to use middleware for access to request.user
        user = await user_manager.get_user(request.user)

        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Unable to load user with ID '{await user_manager.get_user_id(request.user)}'."
            )

        data = await user_manager.get_personal_data(user)
        data.update({'authenticator_key': await user_manager.get_authenticator_key(user)})
        return Response(
            json.dumps(data, indent=4),
            status_code=status.HTTP_200_OK,
            headers={'content-disposition': f"attachment; filename*=utf-8''{quote('personal-data.json')}"},
            media_type='application/json'
        )

    return router


def get_delete_personal_data_router(body_type: BodyType = BodyType.FormData, ) -> APIRouter:
    """

    ## Example

    ```python
    from fastapi import FastAPI

    app = FastAPI()

    app.include_router(get_delete_personal_data_router())
    ```

    :param body_type: Response body.
    :return:
    """
    router = APIRouter()

    @router.delete(
        '/delete-personal-data',
        name='account:delete-personal-data',
        status_code=status.HTTP_200_OK,
        dependencies=[Authorize()],
        responses={
            status.HTTP_404_NOT_FOUND: http_exception_openapi_scheme(
                'Not Found',
                'User not found.'
            )
        },
        summary='Delete account',
    )
    async def delete_personal_data(
            request: Request,
            password: Annotated[SecretStr, body_type()],
            user_manager: UserManager,
            signin_manager: SignInManager
    ):
        """Delete personal data (account) for current user."""
        # Need to use middleware for access to request.user
        user = await user_manager.get_user(request.user)

        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Unable to load user with ID '{await user_manager.get_user_id(request.user)}'."
            )

        check_password_result = await user_manager.check_password(user, password.get_secret_value())

        if not check_password_result:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Incorrect password.'
            )

        await user_manager.delete(user)
        await signin_manager.sign_out()

    return router
