from typing import Annotated

from fastapi import Depends
from pydentity_db.stores import UserStore, RoleStore
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncEngine, AsyncSession


def get_engine():
    return create_async_engine('sqlite+aiosqlite:///examples.db')


def get_async_session_maker(engine: Annotated[AsyncEngine, Depends(get_engine)]):
    return async_sessionmaker(engine, expire_on_commit=False)


async def get_session(maker: Annotated[async_sessionmaker[AsyncSession], Depends(get_async_session_maker)]):
    async with maker() as session:
        yield session


def get_user_store(session: Annotated[AsyncSession, Depends(get_session)]):
    return UserStore(session)


def get_role_store(session: Annotated[AsyncSession, Depends(get_session)]):
    return RoleStore(session)
