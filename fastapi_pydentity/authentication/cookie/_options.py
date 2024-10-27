from datetime import timedelta
from typing import Literal


class CookieAuthenticationOptions:
    __slots__ = (
        "domain",
        "httponly",
        "max_age",
        "name",
        "path",
        "samesite",
        "secure",
        "timespan",
        "persistent_timespan",
    )

    def __init__(
            self,
            name: str | None = None,
            timespan: timedelta | None = None,
            max_age: int | None = None,
            path: str = "/",
            domain: str | None = None,
            httponly: bool = True,
            secure: bool = True,
            samesite: Literal["lax", "strict", "none"] = "lax",
            persistent_timespan: timedelta | None = None
    ) -> None:
        self.name = name
        self.timespan = timespan
        self.max_age = max_age
        self.path = path
        self.domain = domain
        self.httponly = httponly
        self.secure = secure
        self.samesite = samesite
        self.persistent_timespan = persistent_timespan or timedelta(days=7)
