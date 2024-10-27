from typing import Annotated

from fastapi import Form, Depends
from pydantic import EmailStr, SecretStr


class RegisterForm:
    def __init__(
            self,
            email: Annotated[
                EmailStr,
                Form(alias="email", validation_alias="email", examples=["user@examples.com"])
            ],
            password: Annotated[
                SecretStr,
                Form(alias="password", validation_alias="password", examples=["P@ssw0rd"])
            ],
            confirm_password: Annotated[
                SecretStr,
                Form(alias="confirmPassword", validation_alias="confirmPassword", examples=["P@ssw0rd"])
            ],
            is_admin: Annotated[bool, Form(alias="isAdmin", validation_alias="isAdmin")]
    ):
        if password.get_secret_value() != confirm_password.get_secret_value():
            raise ValueError("The passwords don't match.")

        self.email = email
        self.password = password
        self.is_admin = is_admin


class LoginForm:
    def __init__(
            self,
            username: Annotated[
                str,
                Form(alias="username", validation_alias="username", examples=["user@examples.com"])
            ],
            password: Annotated[
                SecretStr,
                Form(alias="password", validation_alias="password", examples=["P@ssw0rd"])
            ],
            remember_me: Annotated[bool, Form(alias="rememberMe", validation_alias="rememberMe")]
    ):
        self.username = username
        self.password = password
        self.remember_me = remember_me


RegisterFormDepends = Annotated[RegisterForm, Depends()]
LoginFormDepends = Annotated[LoginForm, Depends()]
