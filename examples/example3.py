from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from pydentity import IdentityOptions
from pydentity_db.models import Model

from examples.base.depends import get_engine, get_user_store, get_role_store
from examples.base.prep import create_roles
from fastapi_pydentity import (
    add_default_identity,
    use_authentication,
    use_authorization,
)
from fastapi_pydentity.routers import (
    get_register_router,
    get_login_router,
    get_reset_password_router,
    get_delete_personal_data_router,
    get_download_personal_data_router,
    get_change_password_router,
    get_two_factor_authenticator_router,
)


async def forgot_password_callback(request, user, user_manager):
    code = await user_manager.generate_password_reset_token(user)
    callback_url = request.url_for('account:reset-password').include_query_params(code=code)
    print(callback_url)


@asynccontextmanager
async def lifespan(_):
    async with get_engine().begin() as conn:
        await conn.run_sync(Model.metadata.create_all)
        await create_roles(conn)
    yield


def confopt(options: IdentityOptions):
    options.signin.required_confirmed_account = False


app = FastAPI(lifespan=lifespan)

add_default_identity(get_user_store, get_role_store).configure_options(confopt)
use_authentication(app)
use_authorization(app)

app.include_router(get_register_router(), tags=["register"])
app.include_router(get_login_router(enable_2fa=True), tags=["login"])
app.include_router(get_reset_password_router(forgot_password_callback), tags=["reset-password"])
app.include_router(get_two_factor_authenticator_router("Pydentity"), tags=["two-factor-authentication"])
app.include_router(get_delete_personal_data_router(), tags=["delete-personal"])
app.include_router(get_download_personal_data_router(), tags=["download-personal"])
app.include_router(get_change_password_router(), tags=["change-password"])

if __name__ == "__main__":
    uvicorn.run("__main__:app")
