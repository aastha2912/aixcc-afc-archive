import sqlite3

from crs import config
from crs.common.aio import Path
from crs.common.sqlite import SQLiteDB

SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS counters (
        task TEXT NOT NULL,
        name TEXT NOT NULL,
        value REAL NOT NULL,
        PRIMARY KEY (task, name)
    )
    """,
]

# acts as a write-through cache
class CounterDB(SQLiteDB):
    # cache = {task: {name: value}}
    cache: dict[str, dict[str, float]]

    def __init__(self, db_path: str | Path = config.DATA_DIR / "counters.sqlite3"):
        super().__init__(db_path, SCHEMA, detect_types=sqlite3.PARSE_DECLTYPES)
        self.cache = {}

    def _task_cache(self, task: str) -> dict[str, float]:
        return self.cache.setdefault(task, {})

    async def _get(self, task: str, name: str) -> float:
        async with self.sqlite_connect() as conn:
            cur = await conn.execute("SELECT value FROM counters WHERE task = ? AND name = ?", (task, name))
            row = await cur.fetchone()
            return row[0] if row else 0.0

    async def get(self, task: str, name: str) -> float:
        cache = self._task_cache(task)
        if (value := cache.get(name)) is None:
            value = await self._get(task, name)
            cache[name] = value
        return value

    async def fetch_add(self, task: str, name: str, amount: float) -> float:
        cache = self._task_cache(task)
        if (value := cache.get(name)) is None:
            value = await self._get(task, name)

        ### no async checkpoints allowed between these lines
            # check cache again, in the `if` block, after the last checkpoint (in case another coroutine updated the cache)
            value = cache.get(name, value)
        # write to our cache (outside the `if` block)
        cache[name] = value + amount
        ### end no checkpoint zone

        async with self.sqlite_connect() as conn:
            _ = await conn.execute("""
                INSERT INTO counters(task, name, value) VALUES(?, ?, ?)
                ON CONFLICT(task, name) DO UPDATE SET value = value + EXCLUDED.value
                """, (task, name, amount),
            )
            await conn.commit()
        return value

    async def set(self, task: str, name: str, value: float):
        cache = self._task_cache(task)
        cache[name] = value

        async with self.sqlite_connect() as conn:
            _ = await conn.execute("""
                INSERT INTO counters(task, name, value) VALUES(?, ?, ?)
                ON CONFLICT(task, name) DO UPDATE SET value = EXCLUDED.value
                """, (task, name, value),
            )
            await conn.commit()

    async def add(self, task: str, name: str, amount: float) -> None:
        _ = await self.fetch_add(task, name, amount)

    def view(self, task: str) -> "CounterView":
        return CounterView(self, task)

class CounterView:
    db: CounterDB
    task: str

    def __init__(self, db: CounterDB, task: str):
        self.db = db
        self.task = task

    async def get(self, name: str) -> float:
        return await self.db.get(self.task, name)

    async def set(self, name: str, value: float):
        return await self.db.set(self.task, name, value)

    async def fetch_add(self, name: str, amount: float) -> float:
        return await self.db.fetch_add(self.task, name, amount)

    async def add(self, name: str, amount: float) -> None:
        await self.db.add(self.task, name, amount)

class MockCounterView(CounterView):
    """Mimics the async float counters interface entirely in RAM."""
    def __init__(self):
        self._data: dict[str, float] = {}

    async def set(self, name: str, value: float):
        self._data[name] = value

    async def get(self, name: str) -> float:
        if name not in self._data:
            await self.set(name, 0)
        return self._data[name]

    async def add(self, name: str, amount: float) -> None:
        await self.set(name, await self.get(name) + amount)

    async def fetch_add(self, name: str, amount: float) -> float:
        await self.set(name, (old := await self.get(name)) + amount)
        return old