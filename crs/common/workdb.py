from abc import ABC, abstractmethod
import aiosqlite
import asyncio
import datetime
import enum
import heapq
import itertools
import orjson
import sqlite3

from collections import defaultdict
from dataclasses import dataclass
from crs_rust import logger
from crs.common.aio import Path
from typing import Any, Awaitable, Callable, Self, Optional
from uuid import UUID

from crs import config
from crs.common.scheduler import Scheduler
from crs.common.sqlite import SQLiteDB
from crs.common.types import CRSError, Result, Priority, Err
from crs.common.utils import finalize, bytes_to_uuid
from crs.common.workdb_meta import cur_job_id, cur_job_priority, cur_job_task, cur_job_worktype

DEFAULT_MAX_ATTEMPTS = 3
RETRY_DELAY_BASE = 2
MAX_RETRY_DELAY = 60

sqlite3.register_converter("DATETIME", lambda v: datetime.datetime.fromisoformat(v.decode()))
aiosqlite.register_adapter(UUID, str)
aiosqlite.register_converter("UUID", bytes_to_uuid)

SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS jobs (
        id INTEGER PRIMARY KEY,
        task_id UUID NOT NULL,
        status INTEGER NOT NULL,
        worktype INTEGER NOT NULL,
        task_desc JSONB NOT NULL,
        failure_count INTEGER DEFAULT 0,
        added DATETIME DEFAULT CURRENT_TIMESTAMP,
        expiration DATETIME NOT NULL,  /* after this point, the task is useless and should be discarded */
        priority REAL NOT NULL /* smaller values are higher logical priority */
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_job_unique ON jobs(task_id, worktype, task_desc)",
]
type CallBack[T] = Callable[[T], Awaitable[Result[None]]]

job_metric = config.metrics.create_counter("work-jobs")
util_metric = config.metrics.create_gauge("work-util")
count_metric = config.metrics.create_gauge("work-count")

class JobStatus(enum.Enum):
    SUBMITTED = enum.auto()
    RUNNING = enum.auto()
    DONE = enum.auto()
    FAILED = enum.auto()
    EXPIRED = enum.auto()
    CANCELLED = enum.auto()

    def __conform__(self, protocol: Any):
        if protocol is sqlite3.PrepareProtocol:
            return int(self.value)

# what type of structured data does the work take, and how much parallelization does it support
@dataclass
class WorkDesc[R]:
    limit: int
    timeout: float
    cls: type[R]
    silent: bool = False
    attempts: Optional[int] = DEFAULT_MAX_ATTEMPTS
    batchsize: Optional[int] = None

@dataclass(slots=True)
class Job[W: enum.IntEnum]:
    id: int
    task_id: UUID
    worktype: W
    data: Any
    expiration: datetime.datetime
    priority: float
    status: JobStatus
    failure_count: int

    def track_count(self, n: int) -> None:
        job_metric.add(n, {"type": self.worktype.name, "status": self.status.name})

    def set_status(self, status: JobStatus) -> None:
        self.track_count(-1)
        self.status = status
        self.track_count(1)

    def __hash__(self) -> int:
        return id(self)

    def __lt__(self, other: Self) -> bool:
        return self.priority < other.priority

@dataclass
class Event[W: enum.IntEnum]:
    future: asyncio.Future[None]

@dataclass
class AddJobEvent[W: enum.IntEnum](Event[W]):
    job: Job[W]
    unique: bool

type BulkItem[T] = tuple[T, asyncio.Future[Result[None]]]

class BulkTaskWorker[T](ABC):
    """
    Helper for task callbacks which want to wait and handle things in bulk
    """
    # how long (in seconds) to wait for more work after 1 job appears
    delay = 30

    queue: asyncio.Queue[BulkItem[T]]
    futures: set[asyncio.Future[Result[None]]]

    def __init__(self, batchsize: Optional[int]):
        self.queue = asyncio.Queue()
        self.futures = set()
        # if we receive this many work items, stop waiting for more
        self.batchsize = batchsize or 100

    async def enqueue_and_wait(self, work: T) -> Result[None]:
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        self.futures.add(fut)
        await self.queue.put((work, fut))
        try:
            return await fut
        finally:
            self.futures.discard(fut)

    async def run(self):
        loop = asyncio.get_running_loop()
        try:
            while True:
                items: list[BulkItem[T]] = []
                item = await self.queue.get()
                items.append(item)
                deadline = loop.time() + self.delay
                while len(items) < self.batchsize:
                    timeout = deadline - loop.time()
                    try:
                        item = await asyncio.wait_for(self.queue.get(), timeout=timeout)
                        items.append(item)
                    except TimeoutError:
                        items = [item for item in items if not item[1].done()]
                        break
                    if len(items) == self.batchsize:
                        items = [item for item in items if not item[1].done()]
                await self._process(items)
        except asyncio.CancelledError:
            self.queue.shutdown(immediate=True)
            for fut in self.futures:
                _ = fut.cancel()
            self.futures.clear()
            raise

    async def _process(self, items: list[BulkItem[T]]):
        try:
            results = await self._handle_work([t for t, _ in items])
            for (_, fut), r in zip(items, results, strict=True):
                if not fut.done():
                    fut.set_result(r)
        except Exception as e:
            logger.exception(f"{self.__class__.__name__}: exception while processing bulk queue: {e!r}", e)
            for _, fut in items:
                if not fut.done():
                    fut.set_exception(e)
            raise

    @abstractmethod
    async def _handle_work(self, work: list[T]) -> list[Result[None]]:
        ...

class WorkDB[W: enum.IntEnum](SQLiteDB):
    WORK_DESCS: dict[W, WorkDesc[Any]] = {}

    def __init__(self, worktype: type[W], db_path: str | Path = config.DATA_DIR / "work.sqlite3"):
        super().__init__(db_path, SCHEMA, detect_types=sqlite3.PARSE_DECLTYPES)
        self.worktype_cls = worktype
        self.callbacks: dict[W, CallBack[Any]] = {}

        worktypes = self.WORK_DESCS.keys()
        self.work_counts: dict[W, int] = {k: 0 for k in worktypes}
        self.work_limits: dict[W, int] = {
            k: v.limit for k, v in self.WORK_DESCS.items()
        }
        self.task_work_counts: dict[tuple[UUID, W], int] = {}

        self.cancelled: set[UUID] = set()
        self.running_tasks: defaultdict[UUID, set[asyncio.Task[Any]]] = defaultdict(set)
        self.wakeup = asyncio.Event()

        self.loop_started = asyncio.Event()
        self.next_jobid: Optional[itertools.count[int]] = None

        self.event_queue: list[Event[W]] = []
        self.dirty_job_queue: set[Job[W]] = set()
        self.schedulers: dict[W, Scheduler[UUID]] = {
            worktype: Scheduler() for worktype in worktypes
        }
        self.job_queues: dict[tuple[W, UUID], list[Job[W]]] = {}

    def register_work_callback(self, worktype: W, callback: CallBack[Any]):
        assert worktype not in self.callbacks, "worktypes must have a single, canonical callback"
        self.callbacks[worktype] = callback

    async def submit_job(
        self,
        task_id: UUID,
        worktype: W,
        workdata: Any,
        expiration: datetime.datetime,
        priority: float = Priority.MEDIUM,
        *,
        # use sparingly
        unique: bool = False,
    ) -> None:
        # TODO: is is possible to refactor to enable static type checking? I suspect not easily
        assert isinstance(workdata, self.WORK_DESCS[worktype].cls), "invalid data for job submission"

        _ = await self.loop_started.wait()
        next_jobid = self.next_jobid
        assert next_jobid is not None, "next_jobid is created during loop setup"

        loop = asyncio.get_running_loop()
        future = loop.create_future()
        rowid = next(next_jobid)
        job = Job(
            id=rowid,
            task_id=task_id,
            worktype=worktype,
            data=workdata,
            expiration=expiration,
            priority=priority,
            status=JobStatus.SUBMITTED,
            failure_count=0,
        )
        event = AddJobEvent(
            future=future,
            job=job,
            unique=unique,
        )
        self.event_queue.append(event)
        self.wakeup.set()

        await future

    def kickoff(
        self,
        tg: asyncio.TaskGroup,
        worktype: W,
        work_desc: WorkDesc[Any],
        task_id: UUID,
        job: Job[W],
    ) -> None:
        """
        handle a task with its appropriate callback.
        """
        task_key = (task_id, worktype)

        async def task_entry(fut: Awaitable[Result[None]]) -> Result[None]:
            if job.failure_count > 0:
                await asyncio.sleep(min(MAX_RETRY_DELAY, RETRY_DELAY_BASE**job.failure_count))

            work_token = cur_job_worktype.set(worktype)
            task_token = cur_job_task.set(task_id)
            job_token = cur_job_id.set(job.id)
            prio_token = cur_job_priority.set(job.priority)
            failed = False
            async def done():
                if job.status != JobStatus.RUNNING:
                    pass # something else already changed the status
                elif failed:
                    job.failure_count += 1
                    if work_desc.attempts is not None and job.failure_count >= work_desc.attempts:
                        job.set_status(JobStatus.FAILED)
                    else:
                        job.set_status(JobStatus.SUBMITTED)
                        self._add_job(job)
                    self.dirty_job_queue.add(job)
                else:
                    if job.task_id in self.cancelled:
                        job.set_status(JobStatus.CANCELLED)
                    else:
                        job.set_status(JobStatus.SUBMITTED)
                        self._add_job(job)
                    self.dirty_job_queue.add(job)
                self.work_counts[worktype] -= 1
                task_count = self.task_work_counts[task_key]
                if task_count > 1:
                    self.task_work_counts[task_key] -= 1
                else:
                    del self.task_work_counts[task_key]
                self.schedulers[worktype].finish(job.task_id)
                self.wakeup.set()
            try:
                async with finalize(done()):
                    expires_in = (job.expiration - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
                    try:
                        async with asyncio.timeout(min(work_desc.timeout, expires_in)):
                            res = await fut
                        match res:
                            case Err(e):
                                failed = True
                                if not work_desc.silent:
                                    logger.exception(f"{worktype.name} job {job.id} returned Err", exception=e)
                            case _:
                                job.set_status(JobStatus.DONE)
                                self.dirty_job_queue.add(job)
                        return res
                    except Exception:
                        failed = True
                        raise
            except Exception as e:
                logger.exception(f"exception in event handling job {job.id}", exception=e)
                return Err(CRSError(repr(e)))
            finally:
                cur_job_priority.reset(prio_token)
                cur_job_id.reset(job_token)
                cur_job_task.reset(task_token)
                cur_job_worktype.reset(work_token)

        task = tg.create_task(task_entry(self.callbacks[worktype](job.data)), name=f"{worktype.name}-{job.id}")
        running_tasks = self.running_tasks[job.task_id]
        running_tasks.add(task)
        task.add_done_callback(running_tasks.discard)
        self.work_counts[worktype] += 1
        self.task_work_counts[task_key] = self.task_work_counts.get(task_key, 0) + 1

    async def cancel_tasks(self, task_id: UUID):
        self.cancelled.add(task_id)
        for task in self.running_tasks[task_id]:
            _ = task.cancel()

    async def setup(self) -> None:
        async with self.sqlite_connect() as conn:
            # move jobs from RUNNING -> SUBMITTED on startup
            # TODO: can we mark these jobs as lower priority, in case they were responsible for a crash?
            _ = await conn.execute(
                """
                UPDATE jobs
                SET status = (?)
                WHERE status = (?)
                """,
                (JobStatus.SUBMITTED, JobStatus.RUNNING)
            )

            # handle rowid ourselves so we never need to read it on insert
            async with await conn.execute("SELECT max(id) FROM jobs") as cursor:
                row = await cursor.fetchone()
                maxid = 0 if not row else row[0]
                self.next_jobid = itertools.count((maxid or 0) + 1)

            # hydrate job counts from db
            for w in self.worktype_cls:
                for j in JobStatus:
                    job_metric.add(0, {"type": w.name, "status": j.name})

            async with await conn.execute("SELECT worktype, status, count(*) FROM jobs GROUP BY worktype, status") as cursor:
                async for worktype_int, status_int, count in cursor:
                    try:
                        worktype_enum = self.worktype_cls(worktype_int)
                        status_enum = JobStatus(status_int)
                    except ValueError:
                        continue
                    job_metric.add(count, {"type": worktype_enum.name, "status": status_enum.name})

            # hydrate submitted jobs from db
            async with await conn.execute(
                f"""
                SELECT id, task_id, status, worktype, task_desc, failure_count, expiration, priority FROM jobs
                WHERE status = (?)
                ORDER BY worktype, task_id, failure_count, priority, added ASC
                """,
                (JobStatus.SUBMITTED,),
            ) as cursor:
                async for wid, task_id, _status, worktype_int, task_desc, failure_count, expiration, priority in cursor:
                    worktype = self.worktype_cls(worktype_int)
                    task_data = self.WORK_DESCS[worktype].cls(**orjson.loads(task_desc))
                    job = Job(
                        id=wid,
                        task_id=task_id,
                        worktype=self.worktype_cls(worktype),
                        data=task_data,
                        expiration=expiration,
                        priority=priority,
                        status=JobStatus.SUBMITTED,
                        failure_count=failure_count,
                    )
                    self._add_job(job)

    def _add_job(self, job: Job[W]) -> None:
        job_queue = self.job_queues.setdefault((job.worktype, job.task_id), [])
        heapq.heappush(job_queue, job)
        self.schedulers[job.worktype].add(job.task_id)

    async def process_events(self) -> None:
        events, self.event_queue = self.event_queue, []
        dirty, self.dirty_job_queue = self.dirty_job_queue, set()
        self.wakeup.clear()

        BATCHSIZE = 20000

        async with self.sqlite_connect() as conn:
            pending_adds: list[tuple[bytes, Job[W]]] = []
            async def commit_adds():
                _ = await conn.executemany(
                    """
                    INSERT INTO jobs (id, task_id, worktype, task_desc, expiration, priority, status, failure_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [(job.id, job.task_id, job.worktype, job_data, job.expiration, job.priority, job.status, job.failure_count)
                     for job_data, job in pending_adds]
                )
                await conn.commit()
                pending_adds.clear()

            for event in events:
                match event:
                    case AddJobEvent(job=job, unique=unique):
                        job_data = orjson.dumps(job.data)
                        if unique:
                            async with await conn.execute("SELECT id FROM jobs WHERE task_id=? AND worktype=? AND task_desc=?", (job.task_id, job.worktype, job_data)) as cursor:
                                if (await cursor.fetchone()) is not None:
                                    continue # skip this event

                        self._add_job(job)
                        job.track_count(1)
                        pending_adds.append((job_data, job))
                    case Event():
                        pass # unreachable superclass

                if len(pending_adds) >= BATCHSIZE:
                    await commit_adds()

            if pending_adds:
                await commit_adds()

            dirty = list(dirty)
            for i in range(0, len(dirty), BATCHSIZE):
                _ = await conn.executemany(
                    """
                    UPDATE jobs SET status=?, failure_count=?
                    WHERE id=?
                    """,
                    [(job.status, job.failure_count, job.id) for job in dirty[i:i+BATCHSIZE]],
                )
                await conn.commit()

            for event in events:
                if not event.future.done():
                    event.future.set_result(None)

    async def schedule_step(self, tg: asyncio.TaskGroup) -> None:
        dt_now = datetime.datetime.now(datetime.timezone.utc)
        for worktype, scheduler in self.schedulers.items():
            if worktype not in self.callbacks:
                # TODO: this should be a concerning case to hit
                continue
            # schedule this worktype until we hit global limit or run out of tasks
            while True:
                if self.work_counts[worktype] >= self.work_limits[worktype]:
                    break
                task = scheduler.schedule()
                if task is None:
                    # no work available
                    break
                queue = self.job_queues[worktype, task]

                job = queue[0]
                work_desc = self.WORK_DESCS[job.worktype]
                if (batchsize := work_desc.batchsize) is not None:
                    if self.task_work_counts.get((task, worktype), 0) >= batchsize:
                        # out of batch slots, put the task back in the scheduler and skip for now
                        scheduler.finish(task)
                        scheduler.add(task)
                        break

                # TODO: consider presorted buckets instead of full heap queue if this needs to be faster
                #       also want sampling over the priority for float probability-based priorities
                _ = heapq.heappop(queue)
                if not queue:
                    del self.job_queues[worktype, task]

                new_status: JobStatus = JobStatus.RUNNING
                if dt_now > job.expiration:
                    new_status = JobStatus.EXPIRED
                elif job.task_id in self.cancelled:
                    new_status = JobStatus.CANCELLED

                job.set_status(new_status)
                self.dirty_job_queue.add(job)
                if new_status == JobStatus.RUNNING:
                    self.kickoff(tg, worktype, work_desc, task, job)
                else:
                    scheduler.finish(task)

        for worktype, value in self.work_counts.items():
           count_metric.set(value, {"type": worktype.name})
           util_metric.set(value / self.work_limits[worktype], {"type": worktype.name})

    async def loop(self) -> None:
        await self.setup()
        self.loop_started.set()

        async with asyncio.TaskGroup() as tg:
            while True:
                await self.process_events()
                await self.schedule_step(tg)
                _ = await self.wakeup.wait()
