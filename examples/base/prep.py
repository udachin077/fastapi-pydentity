from uuid import uuid4

from pydentity_db.models import IdentityRole
from sqlalchemy import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection


async def create_roles(connection: AsyncConnection):
    try:
        await connection.execute(
            insert(IdentityRole),
            [
                {"id": str(uuid4()), "name": "admin", "normalized_name": "ADMIN"},
                {"id": str(uuid4()), "name": "user", "normalized_name": "USER"},
            ]
        )
        await connection.commit()
    except IntegrityError:
        pass
