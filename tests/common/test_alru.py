import asyncio
import time
import gc
import jsonpickle
import weakref
from typing import Any

from crs.common.types import Err, CRSError
from crs.common.alru import async_once, alru_cache

async def test_async_once_serial():
    hits = 0

    @async_once
    async def once() -> int:
        nonlocal hits
        hits += 1
        return value

    value = 0
    assert (await once()) == value

    for i in range(10):
        value = i
        assert await once() == 0

    assert hits == 1


async def test_async_once_concurrent():
    hits = 0

    @async_once
    async def once() -> int:
        nonlocal hits
        hits += 1
        await asyncio.sleep(0.100)
        return value

    value = 0
    tasks = []
    start = time.perf_counter()
    async with asyncio.TaskGroup() as tg:
        for i in range(10):
            tasks.append(tg.create_task(once()))

        for task in tasks:
            assert (await task) == 0
    assert time.perf_counter() - start < 0.200

    start = time.perf_counter()
    await once()
    assert (time.perf_counter() - start) < 0.100


async def test_alru_serial():
    @alru_cache(maxsize=None)
    async def add(a: int, *, b: int) -> int:
        return a + b

    stats = add.__alru_stats__
    for i in range(3):
        value = await add(i, b=i)
        assert value == (i + i)
    assert stats.hits == 0
    assert stats.misses == 3

    for i in range(3):
        value = await add(i, b=i)
        assert value == (i + i)
    assert stats.hits == 3

    @alru_cache(maxsize=4)
    async def add_limit(a: int, *, b: int) -> int:
        return a + b
    stats = add_limit.__alru_stats__

    for i in range(4):
        value = await add_limit(i, b=i)
        assert value == (i + i)
    assert stats.hits == 0
    assert stats.misses == 4

    for i in range(4):
        value = await add_limit(i, b=i)
        assert value == (i + i)
    assert stats.hits == 4

    assert stats.evictions == 0
    for i in range(10):
        value = await add_limit(i, b=i)
        assert value == (i + i)

    assert stats.cursize == 4
    assert stats.maxsize == 4
    assert stats.evictions == 6


async def test_alru_concurrent():
    @alru_cache(maxsize=None)
    async def add(a: int, *, b: int) -> int:
        await asyncio.sleep(0.100)
        return a + b
    stats = add.__alru_stats__

    OUTER = 4
    INNER = 10

    # uncached
    start = time.perf_counter()
    async with asyncio.TaskGroup() as tg:
        tasks = []
        for i in range(OUTER):
            for j in range(INNER):
                tasks.append((i, tg.create_task(add(i, b=i))))

        for (i, task) in tasks:
            assert (await task) == (i + i)
    assert time.perf_counter() - start < 0.200
    assert stats.hits == (INNER * OUTER) - OUTER
    assert stats.misses == OUTER

    # cached
    start = time.perf_counter()
    async with asyncio.TaskGroup() as tg:
        tasks = []
        for i in range(OUTER):
            for j in range(INNER):
                tasks.append((i, tg.create_task(add(i, b=i))))

        for i, task in tasks:
            assert (await task) == i + i
    assert time.perf_counter() - start < 0.100

    assert stats.hits == (INNER * OUTER) * 2 - OUTER
    assert stats.misses == OUTER


async def test_alru_eviction_lock():
    @alru_cache(maxsize=1)
    async def f(_: int) -> None:
        await asyncio.sleep(0.005)

    async with asyncio.TaskGroup() as tg:
        for n in (0, 1, 2, 3, 2, 1, 0):
            _ = tg.create_task(f(n))


async def test_alru_instance_cache():
    class Foo:
        @alru_cache(maxsize=None)
        async def foo(self, x: int, *args: Any):
            return x

    instances = [Foo() for _ in range(2)]
    for i in range(2):
        for j in range(4):
            assert await instances[i].foo(j, instances[i]) == j
        assert instances[i].foo.__alru_stats__.misses == 4
        for j in range(4):
            assert await instances[i].foo(j, instances[i]) == j
        assert instances[i].foo.__alru_stats__.hits == 4

    weak = weakref.ref(instances[1])
    assert weak() is not None
    del instances[1]
    _ = gc.collect()
    assert weak() is None, "instance could not be collected"
    assert instances[0].foo.__alru_stats__.hits == 4

async def test_async_instance_once():
    calls: list['Foo'] = []
    class Foo:
        @async_once
        async def foo(self):
            nonlocal calls
            calls.append(self)

    instances = [Foo() for _ in range(2)]
    for i in range(2):
        for _ in range(4):
            await instances[i].foo()
    assert calls == instances, "unexpected call order"
    del calls

    weak = weakref.ref(instances[1])
    assert weak() is not None
    del instances[1]
    _ = gc.collect()
    assert weak() is None, "instance could not be collected"

class Serializable:
    MAGIC = "THISISAMAGICSTRING"
    def __init__(self):
        self.calls = 0

    @async_once
    async def foo(self):
        self.calls += 1
        return self.MAGIC

async def test_alru_instance_serialization():
    obj = Serializable()
    assert await obj.foo() == Serializable.MAGIC # cache the result
    assert await obj.foo() == Serializable.MAGIC
    assert obj.calls == 1

    encoded: str = jsonpickle.encode(obj) # type: ignore
    assert Serializable.MAGIC not in encoded, "return result of cached method in serialized obj"

    obj2: Serializable = jsonpickle.decode(encoded) # type: ignore
    assert obj2.calls == 1
    assert await obj2.foo() == Serializable.MAGIC # re-cache the result in the new instance
    assert obj2.calls == 2, "result was somehow already cached in deserialized obj?"
    assert await obj2.foo() == Serializable.MAGIC # it should be cached now
    assert obj2.calls == 2, "could not cache in the new instance"

async def test_alru_filtering():
    @alru_cache(filter=lambda x: x == 1)
    async def f(x: int) -> int:
        return x

    await f(0)
    assert f.__alru_stats__.cursize == 0
    await f(2)
    assert f.__alru_stats__.cursize == 0
    await f(1)
    assert f.__alru_stats__.cursize == 1
    await f(2)
    assert f.__alru_stats__.cursize == 1
    await f(0)
    assert f.__alru_stats__.cursize == 1


async def test_alru_leak_locals():
    class A(): pass
    x = A()

    @alru_cache()
    async def err() -> Err[CRSError]:
        return Err(CRSError('asdf'))

    async def foo(x: A):
        return await err()

    # cache an err with a traceback for frames holding x (note x is not in the cache key)
    e = await foo(x)

    # ensure a second call hits the cache
    e = await foo(x)
    assert err.__alru_stats__.cursize == 1
    assert err.__alru_stats__.hits == 1

    # try to free x, but it shouldn't collect because e's traceback holds it
    weak = weakref.ref(x)
    del x
    _ = gc.collect()
    assert weak is not None, "x collected even though e is alive"

    # delete e to allow x to be collected
    del e
    _ = gc.collect()

    # ensure x could be collected
    assert weak() is None, "x could not be collected"