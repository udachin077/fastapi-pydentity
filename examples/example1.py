from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException
from pydentity import IdentityOptions
from pydentity.utils import datetime
from pydentity_db.models import Model

from examples.base.depends import get_engine, get_user_store, get_role_store
from examples.endpoints.account import router as account_router
from examples.endpoints.data import router as data_router
from examples.base.schemes import LoginFormDepends
from examples.base.prep import create_roles
from fastapi_pydentity import (
    add_default_identity,
    use_authentication,
    use_authorization,
    add_authentication,
)
from fastapi_pydentity.authentication.bearer import TokenValidationParameters, JWTSecurityToken
from fastapi_pydentity.identity import SignInManagerDepends


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
add_authentication("Bearer").add_jwt_bearer(
    validation_parameters=TokenValidationParameters("secret-token-key")
)
use_authentication(app)
use_authorization(app)


@account_router.post("/login")
async def login(form: LoginFormDepends, signin_manager: SignInManagerDepends):
    result = await signin_manager.password_sign_in(
        form.username,
        form.password.get_secret_value(),
        form.remember_me
    )
    if result.succeeded:
        user = await signin_manager.user_manager.find_by_name(form.username)
        principal = await signin_manager.create_user_principal(user)
        access_token = JWTSecurityToken(
            "secret-token-key",
            claims=principal.claims,
            expires=datetime.utcnow().add_minutes(10)
        )
        return {"access_token": access_token.encode()}

    raise HTTPException(status_code=400, detail=str(result))


@account_router.post("/logout")
async def logout(signin_manager: SignInManagerDepends):
    pass


app.include_router(account_router)
app.include_router(data_router)

if __name__ == "__main__":
    uvicorn.run("__main__:app")
