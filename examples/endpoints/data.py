from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends
from fastapi import Request

from examples.base.schemes import RegisterForm, LoginForm
from fastapi_pydentity import Authorize

RegisterFormDepends = Annotated[RegisterForm, Depends()]
LoginFormDepends = Annotated[LoginForm, Depends()]

router = APIRouter(prefix="/data")


@router.get("")
async def get_data():
    return {"data": uuid4()}


@router.get("/authorized", dependencies=[Authorize()])
async def get_authorized_data(request: Request):
    return {"name": request.user.identity.name}


@router.get("/secure", dependencies=[Authorize("admin")])
async def get_secure_data(request: Request):
    return {"secure_data": request.user.identity.find_first_value("securitystamp")}
