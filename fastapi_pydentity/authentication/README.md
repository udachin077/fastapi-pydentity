

## AuthenticationBuilder

```python
from datetime import timedelta

from fastapi_pydentity.authentication.builder import AuthenticationBuilder, CookieAuthenticationOptions

builder = AuthenticationBuilder()
builder.add_cookie(
    "MyCookie",
    CookieAuthenticationOptions(timespan=timedelta(minutes=5))
)
```

### Cookie
```python

```

### Bearer
```python

```