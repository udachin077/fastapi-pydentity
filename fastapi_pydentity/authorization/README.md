## AuthorizationBuilder

```python
from fastapi_pydentity.authorization.builder import AuthorizationBuilder

builder = AuthorizationBuilder()
```

### Use `AuthorizationPolicy` or `+=`

```python
from pydentity.authorization import AuthorizationPolicyBuilder

location_policy = AuthorizationPolicyBuilder("LocationPolicy").require_claim("location", "London").build()

builder += location_policy
# Equivalent to
builder.add_policy("LocationPolicy", location_policy)
```

### Use `AuthorizationPolicyBuilder`

```python
from pydentity.authorization import AuthorizationPolicyBuilder


def location_policy(b: AuthorizationPolicyBuilder):
    b.require_claim("location", "London")


builder.add_policy("LocationPolicy", location_policy)
```

## AuthorizationMiddleware

Adds `AuthorizationError` handling. Returns `PlainTextResponse("Forbidden", status_code=403)`

```python
from fastapi import FastAPI

from fastapi_pydentity.authorization import use_authorization

app = FastAPI()
use_authorization(app)
```

## Authorize

Prohibits unauthorized access by an unauthorized user to the specified `api`.

```python
from fastapi import FastAPI

from fastapi_pydentity.authorization.params import Authorize

app = FastAPI()


@app.get("/secure", dependencies=[Authorize()])
async def secure_api():
    ...
```

Prohibits unauthorized access by an unauthorized user to the specified `Router`.

```python
from fastapi import APIRouter

from fastapi_pydentity.authorization import Authorize

secure_router = APIRouter(prefix="/secure", dependencies=[Authorize()])


@secure_router.get("", )
async def secure_api():
    ...
```

### Role-based authorization

Authorization checks whether the user matches one of the specified roles.

```python
@app.get("/secure", dependencies=[Authorize("sysadmin,admin")])
async def secure_api():
    ...
```

### Policy authorization

Authorization checks whether the user complies with one of the specified policies.

```python
@app.get("/secure", dependencies=[Authorize(policy="LocationPolicy")])
async def secure_api():
    ...
```

### Role-based and policy authorization

Roles and policies can be used together

```python
@app.get("/secure", dependencies=[Authorize("sysadmin,admin", policy="LocationPolicy")])
async def secure_api():
    ...
```

or combined into one policy

```python
from pydentity.authorization import AuthorizationPolicyBuilder


def local_admin_policy(b: AuthorizationPolicyBuilder):
    b.require_claim("location", "London")
    b.require_role("sysadmin,admin")


builder.add_policy("LocalAdminPolicy", local_admin_policy)


@app.get("/secure", dependencies=[Authorize(policy="LocalAdminPolicy")])
async def secure_api():
    ...
```