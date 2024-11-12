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
        """
        Cookie parameters that will be used by the ``CookieAuthenticationHandler`` to receive and set cookies.

        :param name: A string that will be the cookie's key.
        :param timespan: Timedelta, which defines the interval until the cookie expires.
        :param max_age: An integer that defines the lifetime of the cookie in seconds. A negative integer or a value of 0 will discard the cookie immediately.
        :param path: A string that specifies the subset of routes to which the cookie will apply.
        :param domain: A string that specifies the domain for which the cookie is valid.
        :param httponly: A bool indicating that the cookie cannot be accessed via JavaScript through ``Document.cookie`` property, the ``XMLHttpRequest`` or Request APIs.
        :param secure: A bool indicating that the cookie will only be sent to the server if request is made using SSL and the HTTPS protocol.
        :param samesite: A string that specifies the samesite strategy for the cookie. Valid values are 'lax', 'strict' and 'none'. Defaults to 'lax'.
        :param persistent_timespan: The time interval that will be set when logging in using ``SignInManager`` if the `is_persistent` parameter is set to `True`. Defaults to 7 days.
        """
        self.name = name
        self.timespan = timespan
        self.max_age = max_age
        self.path = path
        self.domain = domain
        self.httponly = httponly
        self.secure = secure
        self.samesite = samesite
        self.persistent_timespan = persistent_timespan or timedelta(days=7)
