from collections import defaultdict
from enum import IntEnum, auto
from pydantic.dataclasses import dataclass
from result import Ok
from typing import Awaitable
import asyncio
import datetime
import tempfile
import uuid

from crs.common import workdb
from crs.common.types import Result
from crs.common.workdb import JobStatus

@dataclass(slots=True)
class TestWorkDesc:
    testid: int
    worktype: int

@dataclass(slots=True)
class TestWorkTaskDesc(TestWorkDesc):
    task: uuid.UUID

class WorkType(IntEnum):
    TESTING1 = auto()
    TESTING2 = auto()

async def test_workdb_normal():
    dbpath = tempfile.NamedTemporaryFile(suffix=".sqlite3")
    class TestWorkDB(workdb.WorkDB[WorkType]):
        WORK_DESCS = {
            WorkType.TESTING1: workdb.WorkDesc(limit=50, timeout=5, cls=TestWorkDesc),
            WorkType.TESTING2: workdb.WorkDesc(limit=10, timeout=5, cls=TestWorkDesc),
        }

    db = TestWorkDB(WorkType, dbpath.name)

    completed: list[int] = []

    active = [0, 0]
    highmark = [0, 0]

    async def workfunc(t: TestWorkDesc) -> Result[None]:
        active[t.worktype] += 1
        highmark[t.worktype] = max(active[t.worktype], highmark[t.worktype])
        print(f"running {t.testid}, {active}, {highmark}")
        await asyncio.sleep(0.5)
        print(f"done sleeping for {t.testid}")
        active[t.worktype] -= 1
        completed.append(t.testid)
        return Ok(None)

    db.register_work_callback(WorkType.TESTING1, workfunc)
    db.register_work_callback(WorkType.TESTING2, workfunc)

    task_id = uuid.uuid4()

    async with asyncio.TaskGroup() as tg:
        loop = tg.create_task(db.loop())

        job_futs: list[Awaitable[None]] = []
        for i in range(100):
            job_futs.append(db.submit_job(
                task_id,
                WorkType.TESTING1,
                TestWorkDesc(testid=i, worktype=0),
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
            ))
        for i in range(20):
            job_futs.append(db.submit_job(
                task_id,
                WorkType.TESTING2,
                TestWorkDesc(testid=i, worktype=1),
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
            ))
        _ = await asyncio.gather(*job_futs)

        jobs1 = db.job_queues[(WorkType.TESTING1, task_id)]
        jobs2 = db.job_queues[(WorkType.TESTING2, task_id)]
        assert len(jobs1) == 100
        assert len(jobs2) == 20
        jobs = jobs1 + jobs2

        try:
            async with asyncio.timeout(6):
                while len(completed) < len(jobs):
                    await asyncio.sleep(0.1)
        except TimeoutError:
            pass

        _ = loop.cancel()

    assert highmark[0] == 50
    assert highmark[1] == 10
    assert len(completed) == 120

    for job in jobs:
        assert job.status == JobStatus.DONE

async def test_workdb_task_limits():
    dbpath = tempfile.NamedTemporaryFile(suffix=".sqlite3")
    class TestWorkDB(workdb.WorkDB[WorkType]):
        WORK_DESCS = {
            WorkType.TESTING1: workdb.WorkDesc(limit=20, timeout=5, cls=TestWorkTaskDesc),
            WorkType.TESTING2: workdb.WorkDesc(limit=10, timeout=5, cls=TestWorkTaskDesc),
        }

    db = TestWorkDB(WorkType, dbpath.name)

    completed: list[int] = []

    active: dict[tuple[int, uuid.UUID], int] = defaultdict(int)
    highmark: dict[tuple[int, uuid.UUID], int] = defaultdict(int)

    async def workfunc(t: TestWorkTaskDesc) -> Result[None]:
        active[t.worktype, t.task] += 1
        highmark[t.worktype, t.task] = max(active[t.worktype, t.task], highmark[t.worktype, t.task])
        print(f"running {t.testid}, {active}, {highmark}")
        await asyncio.sleep(0.5)
        print(f"done sleeping for {t.testid}")
        active[t.worktype, t.task] -= 1
        completed.append(t.testid)
        return Ok(None)

    db.register_work_callback(WorkType.TESTING1, workfunc)
    db.register_work_callback(WorkType.TESTING2, workfunc)

    task_id = uuid.uuid4()
    task_id2 = uuid.uuid4()

    async with asyncio.TaskGroup() as tg:
        loop = tg.create_task(db.loop())

        job_futs: list[Awaitable[None]] = []
        for i in range(50):
            job_futs.append(db.submit_job(
                task_id,
                WorkType.TESTING1,
                TestWorkTaskDesc(testid=i, task=task_id, worktype=0),
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
            ))
        for i in range(50):
            job_futs.append(db.submit_job(
                task_id2,
                WorkType.TESTING1,
                TestWorkTaskDesc(testid=i, task=task_id2, worktype=0),
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
            ))
        for i in range(20):
            job_futs.append(db.submit_job(
                task_id,
                WorkType.TESTING2,
                TestWorkTaskDesc(testid=i, task=task_id, worktype=1),
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
            ))
        _ = await asyncio.gather(*job_futs)

        jobs1 = db.job_queues[(WorkType.TESTING1, task_id)] + db.job_queues[(WorkType.TESTING1, task_id2)]
        jobs2 = db.job_queues[(WorkType.TESTING2, task_id)]
        assert len(jobs1) == 100
        assert len(jobs2) == 20
        jobs = jobs1 + jobs2

        try:
            async with asyncio.timeout(6):
                while len(completed) < len(jobs):
                    await asyncio.sleep(0.1)
        except TimeoutError:
            pass

        _ = loop.cancel()

    # support a range in case our slow CI doesn't reach max parallelism
    assert max(highmark[0, task_id], highmark[0, task_id2]) >= 10
    assert highmark[1, task_id] == 10
    assert len(completed) == 120

    for job in jobs:
        assert job.status == JobStatus.DONE

async def test_workdb_timeouts():
    dbpath = tempfile.NamedTemporaryFile(suffix=".sqlite3")
    class TestWorkDB(workdb.WorkDB[WorkType]):
        WORK_DESCS = { WorkType.TESTING1: workdb.WorkDesc(limit=50, timeout=0.1, cls=TestWorkDesc) }
    db = TestWorkDB(WorkType, dbpath.name)

    run_count = 0
    JOBS = 10
    target_runs = workdb.DEFAULT_MAX_ATTEMPTS * JOBS

    async def workfunc(t: TestWorkDesc) -> Result[None]:
        nonlocal run_count
        run_count += 1
        try:
            print(f"running {t.testid}")
        except asyncio.CancelledError:
            print(f"cancelled {t.testid}")
            raise
        await asyncio.sleep(1.0)
        print(f"done sleeping for {t.testid}")
        return Ok(None)

    db.register_work_callback(WorkType.TESTING1, workfunc)

    task_id = uuid.uuid4()

    async with asyncio.TaskGroup() as tg:
        loop = tg.create_task(db.loop())
        job_futs = [db.submit_job(
                        task_id,
                        WorkType.TESTING1,
                        TestWorkDesc(testid=i, worktype=0),
                        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
                    ) for i in range(JOBS)]
        await asyncio.gather(*job_futs)
        jobs = db.job_queues[(WorkType.TESTING1, task_id)].copy()
        assert len(jobs) == JOBS

        try:
            async with asyncio.timeout(20):
                while run_count < target_runs or db.job_queues.get((WorkType.TESTING1, task_id)) or db.running_tasks:
                    await asyncio.sleep(0.1)
        except TimeoutError:
            pass
        _ = loop.cancel()

    assert run_count == target_runs

    for job in jobs:
        assert job.status == JobStatus.FAILED

async def test_workdb_retry():
    dbpath = tempfile.NamedTemporaryFile(suffix=".sqlite3")
    class TestWorkDB(workdb.WorkDB[WorkType]):
        WORK_DESCS = {
            WorkType.TESTING1: workdb.WorkDesc(limit=50, timeout=1, cls=TestWorkDesc)
        }
    db = TestWorkDB(WorkType, dbpath.name)

    run_count = 0
    JOBS = 10
    failed: set[int] = set()

    async def workfunc(t: TestWorkDesc) -> Result[None]:
        nonlocal run_count
        run_count += 1
        if t.testid not in failed:
            # fail each job once
            print(f"failing {t.testid}")
            failed.add(t.testid)
            assert False
        print(f"passing {t.testid}")
        return Ok(None)

    db.register_work_callback(WorkType.TESTING1, workfunc)

    task_id = uuid.uuid4()

    async with asyncio.TaskGroup() as tg:
        loop = tg.create_task(db.loop())
        job_futs = [db.submit_job(
                        task_id,
                        WorkType.TESTING1,
                        TestWorkDesc(testid=i, worktype=0),
                        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
                    ) for i in range(JOBS)]
        await asyncio.gather(*job_futs)
        jobs = db.job_queues[(WorkType.TESTING1, task_id)].copy()
        assert len(jobs) == JOBS

        try:
            async with asyncio.timeout(6):
                while run_count < JOBS * 2:
                    await asyncio.sleep(0.1)
        except TimeoutError:
            pass
        _ = loop.cancel()

    assert run_count == JOBS * 2

    for job in jobs:
        assert job.status == JobStatus.DONE


async def test_workdb_restart():
    dbpath = tempfile.NamedTemporaryFile(suffix=".sqlite3")

    class TestWorkDB(workdb.WorkDB[WorkType]):
        WORK_DESCS = {WorkType.TESTING1: workdb.WorkDesc(limit=50, timeout=10, cls=TestWorkDesc)}

    flag = asyncio.Event()
    async def workfunc(t: TestWorkDesc) -> Result[None]:
        flag.set()
        return Ok(None)

    db = TestWorkDB(WorkType, dbpath.name)
    db.register_work_callback(WorkType.TESTING1, workfunc)

    async with asyncio.TaskGroup() as tg:
        loop = tg.create_task(db.loop())

        task_id = uuid.uuid4()
        await db.submit_job(
            task_id,
            WorkType.TESTING1,
            TestWorkDesc(testid=0, worktype=0),
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
        )
        jobs = db.job_queues[(WorkType.TESTING1, task_id)]
        assert len(jobs) == 1
        job = jobs[0]

        # wait for our work callback
        _ = await asyncio.wait_for(flag.wait(), timeout=1)
        assert job.status == JobStatus.DONE
        # pretend it's still running
        job.set_status(JobStatus.RUNNING)
        # give loop time to commit
        await asyncio.sleep(1)
        _ = loop.cancel()

    # restart db
    async with asyncio.TaskGroup() as tg:
        db = TestWorkDB(WorkType, dbpath.name)
        db.register_work_callback(WorkType.TESTING1, workfunc)
        loop = tg.create_task(db.loop())
        # wait for our work callback
        _ = await asyncio.wait_for(flag.wait(), timeout=1)
        _ = loop.cancel()


async def test_cancellation():
    dbpath = tempfile.NamedTemporaryFile(suffix=".sqlite3")
    class TestWorkDB(workdb.WorkDB[WorkType]):
        WORK_DESCS = {WorkType.TESTING1: workdb.WorkDesc(limit=50, timeout=10, cls=TestWorkDesc)}
    db = TestWorkDB(WorkType, dbpath.name)

    async def test():
        events: list[asyncio.Event] = [asyncio.Event() for _ in range(2)]
        task_ids = [uuid.uuid4() for _ in range(2)]

        start_barrier = asyncio.Barrier(3)
        finished = asyncio.Event()
        raised = asyncio.Event()
        async def workfunc(t: TestWorkDesc) -> Result[None]:
            try:
                _ = await start_barrier.wait()
                _ = await events[t.testid].wait()
                finished.set()
                return Ok(None)
            except asyncio.CancelledError:
                raised.set()
                raise

        db.register_work_callback(WorkType.TESTING1, workfunc)

        async with asyncio.TaskGroup() as tg:
            loop = tg.create_task(db.loop())

            job_futs = []
            for i in range(2):
                job_futs.append(db.submit_job(
                    task_ids[i],
                    WorkType.TESTING1,
                    TestWorkDesc(testid=i, worktype=0),
                    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
                ))
            await asyncio.gather(*job_futs)
            jobs = [db.job_queues[(WorkType.TESTING1, task_id)][0] for task_id in task_ids]
            assert len(jobs) == 2

            _ = await start_barrier.wait()
            for task_id in task_ids:
                assert len(db.running_tasks[task_id]) == 1

            await db.cancel_tasks(task_ids[0])
            _ = await raised.wait()
            await asyncio.sleep(0.05)
            assert len(db.running_tasks[task_ids[0]]) == 0
            assert len(db.running_tasks[task_ids[1]]) == 1
            assert not finished.is_set()

            events[1].set()
            _ = await finished.wait()
            assert len(db.running_tasks[task_ids[0]]) == 0

            # wait for failed tasks to be re-examined
            await asyncio.sleep(0.5)
            _ = loop.cancel()

        assert jobs[0].status == JobStatus.CANCELLED
        assert jobs[1].status == JobStatus.DONE

    async with asyncio.timeout(10):
        await test()

async def test_bulk_work():
    dbpath = tempfile.NamedTemporaryFile(suffix=".sqlite3")
    class TestWorkDB(workdb.WorkDB[WorkType]):
        WORK_DESCS = {
            WorkType.TESTING1: workdb.WorkDesc(limit=50, timeout=10, cls=TestWorkDesc),
            WorkType.TESTING2: workdb.WorkDesc(limit=500, timeout=10, cls=TestWorkDesc),
        }

    class BulkTestWorkerShort(workdb.BulkTaskWorker[TestWorkDesc]):
        delay = 0.5

        def __init__(self):
            self.inits = 0
            self.handled = 0
            super().__init__(batchsize=None)

        async def _handle_work(self, work: list[TestWorkDesc]) -> list[Result[None]]:
            self.inits += 1
            self.handled += len(work)

            return [Ok(None) for _ in work]

    bulk_worker = BulkTestWorkerShort()
    db = TestWorkDB(WorkType, dbpath.name)
    db.register_work_callback(WorkType.TESTING1, bulk_worker.enqueue_and_wait)

    async with asyncio.TaskGroup() as tg:
        loop = tg.create_task(db.loop())
        bulk_task = tg.create_task(bulk_worker.run())

        task_ids = [uuid.uuid4() for _ in range(20)]
        job_futs = [db.submit_job(
                        task_id,
                        WorkType.TESTING1,
                        TestWorkDesc(testid=i, worktype=0),
                        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
                    ) for i, task_id in enumerate(task_ids)]
        await asyncio.gather(*job_futs)
        jobs = [db.job_queues[(WorkType.TESTING1, task_id)][0] for task_id in task_ids]

        await asyncio.sleep(2)
        _ = loop.cancel()
        _ = bulk_task.cancel()

        assert all(job.status == JobStatus.DONE for job in jobs)
        assert bulk_worker.inits == 1
        assert bulk_worker.handled == 20

    class BulkTestWorkerLong(workdb.BulkTaskWorker[TestWorkDesc]):
        delay = 10

        def __init__(self):
            self.inits = 0
            self.handled = 0
            super().__init__(batchsize=None)

        async def _handle_work(self, work: list[TestWorkDesc]) -> list[Result[None]]:
            self.inits += 1
            self.handled += len(work)

            return [Ok(None) for _ in work]

    bulk_worker = BulkTestWorkerLong()

    db = TestWorkDB(WorkType, dbpath.name)
    db.register_work_callback(WorkType.TESTING2, bulk_worker.enqueue_and_wait)

    async with asyncio.TaskGroup() as tg:
        loop = tg.create_task(db.loop())
        bulk_task = tg.create_task(bulk_worker.run())

        task_ids = [uuid.uuid4() for _ in range(200)]
        job_futs = [db.submit_job(
                        task_id,
                        WorkType.TESTING2,
                        TestWorkDesc(testid=i, worktype=0),
                        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
                    )
                    for i, task_id in enumerate(task_ids)]
        await asyncio.gather(*job_futs)
        jobs = [db.job_queues[(WorkType.TESTING2, task_id)][0] for task_id in task_ids]

        await asyncio.sleep(3)
        _ = loop.cancel()
        _ = bulk_task.cancel()

        assert all(job.status == JobStatus.DONE for job in jobs)
        assert bulk_worker.inits == 2
        assert bulk_worker.handled == 200
