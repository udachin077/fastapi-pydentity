from enum import Enum

from fastapi import Form, Body
from pydantic import BaseModel as _BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class BodyType(Enum):
    FormData = Form
    JSON = Body


class BaseModel(_BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)
