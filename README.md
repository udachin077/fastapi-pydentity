<h1 align="center">FastAPI-Pydentity</h1>

<p align="center">
    <em>Ready-to-use and customizable users management for FastAPI</em>
</p>

## Installation

First you have to install `fastapi-pydentity` like this:

    pip install fastapi-pydentity

You can also install with your db adapter:

For SQLAlchemy:

    pip install fastapi-pydentity[sqlalchemy]

For Tortoise ORM:

    pip install fastapi-pydentity[tortoise]

```python
...

app = FastAPI()

add_default_identity(get_user_store, get_role_store)
use_authentication(app)
use_authorization(app)

...

app.include_router(account_router)
app.include_router(data_router)

```

<div style="background-color: rgb(255, 243, 205); color: black; padding: .8rem; font-size: 1rem;">
<strong>NOTE: </strong>Pydentity is configured before defining routes.
</div>

## Features

* [X] Customizable dependency
* [X] Customizable authentication:
    * [X] Cookie
    * [X] Bearer
* [X] Customizable authorization:
    * [X] Roles
    * [X] Policy






















