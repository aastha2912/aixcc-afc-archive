import random
import asyncio

from crs.common.utils import PrioritySemaphore

async def test_priority_semaphore_order():
    random.seed(0x13371337)
    N = 20
    sem = PrioritySemaphore(N)

    acquires = asyncio.Semaphore(0)
    release = asyncio.Condition()
    async def acquire_and_hold():
        async with sem.scoped(-1):
            acquires.release()
            async with release:
                _ = await release.wait()

    appends = asyncio.Semaphore(0)
    priority_order: list[float] = []
    async def acquire_and_append(priority: float):
        nonlocal priority_order
        acquires.release()
        async with sem.scoped(priority):
            priority_order.append(priority)
            appends.release()

    async with asyncio.TaskGroup() as tg:
        for _ in range(N):
            _ = tg.create_task(acquire_and_hold())

        # wait for all holders to grab semaphore
        for _ in range(N):
            _ = await acquires.acquire()

        assert sem.locked(), "expected sem to be locked after N holders"

        # create append tasks in random order, they should all block trying to acquire
        create_order = list(range(N))
        random.shuffle(create_order)
        for i in create_order:
            _ = tg.create_task(acquire_and_append(i))

        # wait for them all to become sem waiters
        for i in range(N):
            _ = await acquires.acquire()

        assert sem.waiters() == N, "expected sem to hold N waiters"

        # wake a single waiter, freeing a slot to be passed through the append tasks
        async with release:
            release.notify()

        # wait for them all to append
        for _ in range(N):
            _ = await appends.acquire()

        # check that sem was acquired in priority order
        assert sorted(priority_order) == priority_order, "sem acquired in unexpected order"

        # wake the rest of the waiters
        async with release:
            release.notify_all()

async def test_priority_semaphore_cancellation():
    random.seed(0x13371337)
    N = 10
    sem = PrioritySemaphore(0)

    grabs = asyncio.Semaphore(0)
    acquires = asyncio.Semaphore(0)
    cancels = asyncio.Semaphore(0)
    async def grab():
        grabs.release()
        try:
            _ = await sem.acquire(0)
        except asyncio.CancelledError:
            _ = cancels.release()
            raise
        acquires.release()
        sem.release() # pass our slot onto the next

    async with asyncio.TaskGroup() as tg:
        assert sem.locked(), "sem should start locked"

        tasks = [tg.create_task(grab()) for _ in range(N)]

        # wait until all grabs have started
        for _ in range(N):
            _ = await grabs.acquire()

        # cancel half of them randomly
        for task in random.sample(tasks, N//2):
            _ = task.cancel()

        # release a slot to pass through the tasks
        sem.release()

        # wait until all cancels happens
        for _ in range(N//2):
            _ = await cancels.acquire()

        # wait until all acquires happen
        for _ in range(N - N//2):
            _ = await acquires.acquire()

        assert not sem.locked() and sem.waiters() == 0
