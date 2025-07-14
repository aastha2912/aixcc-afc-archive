import aiosqlite
import pathlib

from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional

from crs.app.app_meta import cur_task_exit_stack
from crs.common.aio import Path
from crs.config import metrics

connect_counter = metrics.create_counter("sqlite-connect")

PRAGMAS = [
    "PRAGMA temp_store = memory",
    "PRAGMA journal_mode = WAL",
    "PRAGMA synchronous = NORMAL",
]

def _no_wait() -> None: ...

def sqlite_connect(db_path: pathlib.Path | str, **options: Any) -> aiosqlite.Connection:
    connect_counter.add(1)
    conn = aiosqlite.connect(db_path, **options)
    # make this a non-blocking thread start by patching threading.Thread._started: Event.wait() to be a noop
    conn._started.wait = _no_wait # type: ignore
    return conn

class SQLiteDB:
    def __init__(self, db_path: str | Path, schema: list[str], ro: bool = False, **options: Any):
        self._db_path = str(db_path)
        self._ro = ro
        self._schema = schema
        self._options = options
        self._initialized = False
        self._pinned_connection: Optional[aiosqlite.Connection] = None

    @staticmethod
    async def open_pinned(db_path: str | Path, ro: bool = False):
        db = SQLiteDB(db_path, [], ro=ro)
        if stack := cur_task_exit_stack():
            _ = await stack.enter_async_context(db.sqlite_pin())
        return db

    @asynccontextmanager
    async def sqlite_pin(self) -> AsyncIterator[aiosqlite.Connection]:
        async with sqlite_connect(self._db_path, **self._options) as conn:
            await self._sqlite_on_connect(conn)
            self._pinned_connection = conn
            try:
                yield conn
            finally:
                self._pinned_connection = None

    @asynccontextmanager
    async def sqlite_exclusive(self) -> AsyncIterator[aiosqlite.Connection]:
        async with self.sqlite_pin() as conn:
            _ = await conn.execute("PRAGMA locking_mode = EXCLUSIVE")
            yield conn

    @asynccontextmanager
    async def sqlite_connect(self) -> AsyncIterator[aiosqlite.Connection]:
        if (conn := self._pinned_connection) is not None:
            yield conn
            return

        async with sqlite_connect(self._db_path, **self._options) as conn:
            await self._sqlite_on_connect(conn)
            yield conn

    async def _sqlite_on_connect(self, conn: aiosqlite.Connection) -> None:
        if self._ro:
            _ = await conn.execute("PRAGMA query_only = on")
        else:
            for pragma in PRAGMAS:
                _ = await conn.execute(pragma)
        if not self._initialized:
            for stmt in self._schema:
                _ = await conn.execute(stmt)
            self._initialized = True
