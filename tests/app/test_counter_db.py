from crs.common.aio import tmpdir
from crs.app.counter_db import CounterDB


async def test_basic_counters():
    async with tmpdir() as td:
        db = CounterDB(td / "counters.sqlite3")
        task1 = "A"
        task2 = "B"

        var1 = "C"
        var2 = "D"

        await db.add(task1, var1, 7)
        assert await db.get(task1, var1) == 7
        await db.add(task1, var1, 3)
        assert await db.get(task1, var1) == 10
        await db.set(task1, var1, 3)
        assert await db.get(task1, var1) == 3

        assert await db.get(task2, var1) == 0
        await db.add(task2, var1, -1.3)
        assert await db.get(task2, var1) == -1.3

        assert await db.get(task2, var2) == 0