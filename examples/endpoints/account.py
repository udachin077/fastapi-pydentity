from fastapi import APIRouter
from pydentity_db.models import IdentityUser

from examples.base.schemes import RegisterFormDepends
from fastapi_pydentity.identity import UserManagerDepends

router = APIRouter(prefix="/account")


@router.post("/register")
async def register(form: RegisterFormDepends, user_manager: UserManagerDepends):
    user = IdentityUser(email=form.email, username=form.email)
    result = await user_manager.create(user, form.password.get_secret_value())
    if result.succeeded and form.is_admin:
        await user_manager.add_to_roles(user, "admin")
    return result.succeeded
