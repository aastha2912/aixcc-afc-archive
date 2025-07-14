import json
import sqlite3
import time

from importlib.metadata import version
from crs.common.aio import Path
from typing import Optional
from uuid import UUID

from crs import config
from crs.common.alru import async_once
from crs.common.sqlite import SQLiteDB
from crs.common.utils import bytes_to_uuid
from .models import SARIFBroadcast, SARIFBroadcastDetail, Status, StatusState, StatusTasksState, Task, TaskDetail

import aiosqlite

# convert UUIDs to str
aiosqlite.register_adapter(UUID, str)
aiosqlite.register_converter("UUID", bytes_to_uuid)

SCHEMA = ["""
    CREATE TABLE IF NOT EXISTS tasks (
        id UUID PRIMARY KEY,
        message_id UUID NOT NULL,
        json BLOB NOT NULL
    );
    """, """
    CREATE TABLE IF NOT EXISTS sarifs (
        id UUID PRIMARY KEY,
        message_id UUID NOT NULL,
        json BLOB NOT NULL
    );
    """, """
    CREATE TABLE IF NOT EXISTS statuses (
        id INTEGER PRIMARY KEY,
        json BLOB NOT NULL
    );""", """
    CREATE TABLE IF NOT EXISTS cancellations (
        id UUID PRIMARY KEY
    )
    """
]

class MissingStatusException(Exception):
    pass

class TaskDB(SQLiteDB):
    def __init__(self, db_path: Path = config.DATA_DIR / "tasks.sqlite3"):
        super().__init__(db_path, SCHEMA, detect_types=sqlite3.PARSE_DECLTYPES)

    @async_once
    async def _init(self):
        async with self.sqlite_connect() as conn:
            for stmt in SCHEMA:
                _ = await conn.execute(stmt)

    async def put_tasks(self, task: Task):
        await self._init()
        async with self.sqlite_connect() as conn:
            _ = await conn.executemany(
                """
                INSERT INTO tasks VALUES (?, ?, ?)
                """,
                [(t.task_id, task.message_id, t.model_dump_json()) for t in task.tasks]
            )
            await conn.commit()

    async def get_tasks(self, after: int = -1) -> tuple[int, list[TaskDetail]]:
        await self._init()
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT rowid, json FROM tasks WHERE rowid > (?)
                """,
                (after, )
            )
            tasks: list[TaskDetail] = []
            last_row = after
            async for rowid, json_dat in cur:
                tasks.append(TaskDetail(**json.loads(json_dat)))
                last_row = max(last_row, rowid)

        return last_row, tasks

    async def get_task(self, uuid: UUID) -> Optional[TaskDetail]:
        await self._init()
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT json FROM tasks WHERE id = (?)
                """,
                (uuid, )
            )
            match await cur.fetchone():
                case None:
                    return None
                case json_dat, :
                    return TaskDetail(**json.loads(json_dat))
                case _:
                    return None

    async def put_sarifs(self, sarif: SARIFBroadcast):
        await self._init()
        async with self.sqlite_connect() as conn:
            _ = await conn.executemany(
                """
                INSERT INTO sarifs VALUES (?, ?, ?)
                """,
                [(s.sarif_id, sarif.message_id, s.model_dump_json()) for s in sarif.broadcasts]
            )
            await conn.commit()
            pass

    async def get_sarifs(self, after: int = -1) -> tuple[int, list[SARIFBroadcastDetail]]:
        await self._init()
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT rowid, json FROM sarifs WHERE rowid > (?)
                """,
                (after, )
            )
            sarifs: list[SARIFBroadcastDetail] = []
            last_row = after
            async for rowid, json_dat in cur:
                sarifs.append(SARIFBroadcastDetail(**json.loads(json_dat)))
                last_row = max(last_row, rowid)

        return last_row, sarifs

    async def get_status(self) -> Status:
        await self._init()
        async with self.sqlite_connect() as conn:
            async with conn.execute(
                """
                SELECT json FROM statuses ORDER BY id DESC LIMIT 1
                """
            ) as cursor:
                row = await cursor.fetchone()
                if row is None:
                    raise MissingStatusException("No status in DB")
                return Status(**json.loads(row[0]))

    async def reset_status(self) -> Status:
        await self._init()
        state = StatusState(tasks=StatusTasksState(canceled=0, errored=0, failed=0, pending=0, processing=0, succeeded=0, waiting=0))
        status = Status(details=None, ready=True, since=int(time.time()), state=state, version=version("crs"))
        async with self.sqlite_connect() as conn:
            _ = await conn.execute(
                """
                INSERT INTO statuses (json) VALUES (?)
                """,
                (status.model_dump_json(),)
            )
            await conn.commit()
        return status

    # TODO: method for updating status

    async def cancel_all(self):
        await self._init()
        async with self.sqlite_connect() as conn:
            _ = await conn.execute(
                """
                INSERT OR IGNORE INTO cancellations (id)
                SELECT id FROM tasks
                UNION
                SELECT id FROM sarifs
                """
            )
            await conn.commit()

    async def cancel_task(self, task_id: UUID):
        await self._init()
        async with self.sqlite_connect() as conn:
            _ = await conn.execute(
                """
                INSERT OR IGNORE INTO cancellations (id)
                VALUES (?)
                """,
                (task_id, )
            )
            await conn.commit()

    async def get_cancelled(self, after: int = -1) -> tuple[int, list[UUID]]:
        await self._init()
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT rowid, id FROM cancellations WHERE rowid > (?)
                """,
                (after, )
            )
            ids: list[UUID] = []
            last_row = after
            async for rowid, id in cur:
                ids.append(id)
                last_row = max(last_row, rowid)

        return last_row, ids
