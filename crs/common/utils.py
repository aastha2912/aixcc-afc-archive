import asyncio
import contextlib
import heapq
import functools
import inspect
import os
import uuid

from concurrent.futures import ThreadPoolExecutor
from contextvars import Context
from dataclasses import dataclass
from typing import overload, Awaitable, Callable, Concatenate, Optional, Sequence, Iterable, Iterator, Mapping, Any, Coroutine, Type, Self, TypeVar, Generic, ParamSpec

from .types import Coro, CRSError, Ok, Err, Result, ToolT, ToolSuccess, ToolError, ToolResult
from .core import *
from .shield import SoloTaskGroup, shield_and_wait, finalize # noqa: F401 # pyright: ignore [reportUnusedImport]

from crs_rust import logger

REQUIREABLE_ATTR = "_requireable"

# like Result.unwrap() but raises the inner error instead of an UnwrapError
def require[T](r: Result[T]) -> T:
    # check that the caller is annotated with @requireable
    assert (frame := inspect.currentframe()) is not None, "unexpected call stack"
    assert (frame := frame.f_back) is not None, "unexpected call stack"
    assert (frame := frame.f_back) is not None, "unexpected call stack"
    assert (caller := frame.f_locals.get(frame.f_code.co_name)) and \
           getattr(caller, REQUIREABLE_ATTR, False), \
           "Cannot call require() unless annotated with @requireable"
    match r:
        case Ok(v): return v
        case Err(e): raise e

def rewrite_err(err: CRSError) -> Callable[[CRSError], CRSError]:
    return lambda _: err

@overload
def requireable[**P, R](fn: Callable[P, Result[R]]) -> Callable[P, Result[R]]:
    ...
@overload
def requireable[**P, R](fn: Callable[P, Coro[Result[R]]]) -> Callable[P, Coro[Result[R]]]:
    ...
def requireable[**P, R](fn: Callable[P, Coro[Result[R]] | Result[R]]) -> Callable[P, Coro[Result[R]] | Result[R]]:
    if inspect.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def awrapper(*args: P.args, **kwargs: P.kwargs):
            setattr(awrapper, REQUIREABLE_ATTR, True)
            try:
                res = await fn(*args, **kwargs)
            except CRSError as e:
                return Err(e)
            return res
        return awrapper
    @functools.wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs):
        setattr(wrapper, REQUIREABLE_ATTR, True)
        try:
            res = fn(*args, **kwargs)
        except CRSError as e:
            return Err(e)
        return res
    return wrapper

@requireable
def collect[T](results: Iterable[Result[T]]) -> Result[list[T]]:
    return Ok([require(res) for res in results])

type InspectCallback[**P, R] = Callable[Concatenate[R, P], None]
def inspect_result[**P, R](callback: InspectCallback[P, R]):
    def decorator(fn: Callable[P, Coro[Result[R]]]) -> Callable[P, Coro[Result[R]]]:
        @functools.wraps(fn)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> Result[R]:
            match res := await fn(*args, **kwargs):
                case Ok(r): callback(r, *args, **kwargs)
                case _: pass
            return res
        return wrapper
    return decorator

type PreHook[**P, R] = Callable[P, Coro[Optional[ToolResult[R]]]]
def pre_hook[**P, R](hook: PreHook[P, R]):
    """
    Runs before a tool is called, optionally returning a ToolResult.
    If a ToolResult is returned, it is immediately returned and the tool is not called.
    """
    def decorator(fn: ToolT[P, R]) -> ToolT[P, R]:
        @functools.wraps(fn)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> ToolResult[R]:
            if hook_res := await hook(*args, **kwargs):
                return hook_res
            return await fn(*args, **kwargs)
        return wrapper
    return decorator

type PostHook[**P, R] = Callable[Concatenate[ToolResult[R], P], Coro[ToolResult[R]]]
def post_hook[**P, R](hook: PostHook[P, R]):
    """
    Runs after a tool is called, giving a chance to inspect and/or modify the TooResult.
    """
    def decorator(fn: ToolT[P, R]) -> ToolT[P, R]:
        @functools.wraps(fn)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> ToolResult[R]:
            return await hook(await fn(*args, **kwargs), *args, **kwargs)
        return wrapper
    return decorator

def hook[**P, R](
    fn: ToolT[P, R],
    pre_hooks: Sequence[PreHook[P, R]] = [],
    post_hooks: Sequence[PostHook[P, R]] = []
) -> ToolT[P, R]:
    """
    Hooks a Tool by optionally applying pre_hooks, and post_hooks.
    """
    for hook in pre_hooks: fn = pre_hook(hook)(fn)
    for hook in post_hooks: fn = post_hook(hook)(fn)
    return fn

def to_tool_result[T](result: Result[T]) -> ToolResult[T]:
    match result:
        case Ok(res): return ToolSuccess[T](res)
        case Err(e): return ToolError(e.error, extra=e.extra, action=None)

def tool_wrap[**P, R](
    fn: Callable[P, Coro[Result[R]]],
    inspects: Sequence[InspectCallback[P, R]] = [],
    pre_hooks: Sequence[PreHook[P, R]] = [],
    post_hooks: Sequence[PostHook[P, R]] = []
) -> ToolT[P, R]:
    """
    Wraps a `Result` coroutine function into a tool.
    Optionally applies inspect, pre_hook, and post_hook.
    """
    for inspect in inspects: fn = inspect_result(inspect)(fn)
    @functools.wraps(fn)
    async def wrapper(*args: P.args, **kwargs: P.kwargs) -> ToolResult[R]:
        try:
            return to_tool_result(await fn(*args, **kwargs))
        except CRSError as e:
            return ToolError(e.error, extra=e.extra, action=None)
    return hook(wrapper, pre_hooks=pre_hooks, post_hooks=post_hooks)

async def gather_dict[K, V](input: Mapping[K, Awaitable[V]]) -> dict[K, V]:
    values = await asyncio.gather(*input.values())
    return dict(zip(input.keys(), values))

@dataclass(slots=True)
class PriorityWaiter():
    priority: float
    fut: asyncio.Future[None] # note: could use an Event but it's overkill because we always have at most 1 waiter

    def __lt__(self, other: 'PriorityWaiter'):
        return self.priority < other.priority

class PrioritySemaphore():
    """
    A variant of asyncio.Semaphore which grants waiters their slots
    in priority order rather than FIFO.

    Implementation notes:
        - uses heapq to manage a heap of waiters
        - waiter invariant: at any checkpoint, all waiters either satisfy either
            (a) `waiter in self._waiters and not waiter.done()`, or
            (b) `waiter not in self._waiters and waiter.done()`
    """
    def __init__(self, value: int = 1):
        assert value >= 0, "semaphore value cannot be negative"
        self._value = value
        self._waiters: list[PriorityWaiter] = []

    def locked(self):
        return self._value == 0

    def value(self):
        return self._value

    def waiters(self):
        return len(self._waiters)

    @contextlib.asynccontextmanager
    async def scoped(self, priority: float):
        _ = await self.acquire(priority)
        try:
            yield
        finally:
            self.release()

    async def acquire(self, priority: float):
        if not self.locked():
            self._value -= 1
            return True

        waiter = PriorityWaiter(priority, asyncio.get_running_loop().create_future())
        heapq.heappush(self._waiters, waiter)
        try:
            # shield to avoid propagating cancellation to future (to maintain waiter invariant)
            await asyncio.shield(waiter.fut)
            # normal case: we've been removed from the queue and have the slot, just return
            return True
        except asyncio.CancelledError:
            if waiter.fut.done():
                # cancelled case 1: we've been removed from the queue and have the slot, but got cancelled
                # and must release the slot before re-raising
                self.release()
            else:
                # cancelled case 2: we got cancelled before getting a slot, so we are still in the queue
                # and must remove ourselves before re-raising
                self._waiters.remove(waiter)
                heapq.heapify(self._waiters)
            raise

    def release(self):
        assert self._value >= 0
        if len(self._waiters) == 0:
            # if there are no waiters, increment value to free a slot
            self._value += 1
        else:
            # if there are waiters, transfer our slot to one of them
            # note: if the waiter was cancelled, it will re-release the slot
            waiter = heapq.heappop(self._waiters)
            waiter.fut.set_result(None)

class LimitedTaskGroup(asyncio.TaskGroup):
    def __init__(self, n: int):
        super().__init__()
        self.sem = asyncio.Semaphore(n)

    async def _wrap[T](self, coro: Coroutine[Any, Any, T]):
        async with self.sem:
            return await coro

    def create_task[T](self, coro: Coroutine[Any, Any, T], *, name: Optional[str] = None, context: Optional[Context] = None):
        return super().create_task(self._wrap(coro), name=name, context=context)

@contextlib.contextmanager
def scoped_pipe() -> Iterator[tuple[int, int]]:
    r, w = os.pipe()
    try:
        yield r, w
    finally:
        os.close(r)
        os.close(w)

P = ParamSpec('P')
R = TypeVar('R', covariant=True) # for some reason pyright can't infer covariance if we use type parameter syntax
class cached_property(Generic[P, R], functools.cached_property[R]):
    """
    Wrapper around functools.cached_property that prevents jsonpickle from serializing
    the cached result.

    _jsonpickle_exclude is ignored if the object has a __getstate__ method.

    Note: Ideally we would have a type parameter for self type, but
    functools.cached_property uses Any, so overriding fails typechecks if we don't also
    """
    def __init__(self, func: Callable[Concatenate[Any, P], R]):
        super().__init__(func)

    @overload
    def __get__(self, obj: None, owner: Optional[Type[Any]] = None) -> Self:
        ...
    @overload
    def __get__(self, obj: object, owner: Optional[Type[Any]] = None) -> R:
        ...
    def __get__(self, obj: object, owner: Optional[Type[Any]] = None) -> Self | R:
        if obj is None:
            return super().__get__(None, owner)
        res = super().__get__(obj, owner)
        setattr(obj, '_jsonpickle_exclude', getattr(obj, '_jsonpickle_exclude', set[str]()) | {self.attrname})
        return res

class Executor:
    loop: asyncio.AbstractEventLoop
    executor: ThreadPoolExecutor

    def __init__(self, loop: asyncio.AbstractEventLoop, prefix: str):
        self.loop = loop
        self.executor = ThreadPoolExecutor(1, prefix)

    async def execute_sync[*P, R](self, func: Callable[[*P], R], *args: *P) -> R:
        return await self.loop.run_in_executor(self.executor, func, *args)

    def execute_coro[R](self, coro: Coroutine[Any, Any, R]) -> R:
        assert asyncio._get_running_loop() is None # pyright: ignore [reportPrivateUsage]
        fut = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return fut.result()

def inherit_docs[T, **P, R](cls: Type[T]):
    def decorator(fn: Callable[P, R]) -> Callable[P, R]:
        return functools.update_wrapper(fn, getattr(cls, fn.__name__))
    return decorator

def all_subclasses[T](cls: Type[T]) -> set[type[T]]:
    return set(cls.__subclasses__()).union(
        [s for c in cls.__subclasses__() for s in all_subclasses(c)])

@overload
async def run_coro_batch[T, R](
    coros: Sequence[Coro[T]],
    *,
    name: str,
    filter: Callable[[T], Optional[R]],
    stop_condition: Optional[Callable[[R], bool]] = None
) -> Sequence[R]:
    ...

@overload
async def run_coro_batch[T](
    coros: Sequence[Coro[T]],
    *,
    name: str,
    filter: None = None,
    stop_condition: Optional[Callable[[T], bool]] = None
) -> Sequence[T]:
    ...

async def run_coro_batch[T, R](
    coros: Sequence[Coro[T]],
    *,
    name: str,
    filter: Optional[Callable[[T], Optional[R]]] = None,
    stop_condition: Optional[Callable[[Any], bool]] = None,
) -> Sequence[T | R]:
    """
    Runs a batch of coroutines and aggregates the results.
    Use {stop_condition} if you want to cancel other coroutines once a qualifying result is produced.
    Returns all results that pass the {filter}, or all results if no filter is provided
    """
    pending: set[asyncio.Task[T]] = set()
    results: list[T | R] = []
    async with asyncio.TaskGroup() as tg:
        for i, coro in enumerate(coros):
            pending.add(tg.create_task(coro, name=f"{name} ({i})"))

        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for res in done:
                if res.cancelled():
                    continue
                if res.exception() is not None:
                    logger.warning(f"run_batch - agent encountered exception: {repr(res.exception())}")
                    continue
                res = res.result()
                if filter and (res := filter(res)) is None:
                    continue
                results.append(res)
                if stop_condition and stop_condition(res):
                    for t in pending:
                            _ = t.cancel()
    return results

class ExceptAndLogTaskGroup(asyncio.TaskGroup):
    def create_task[T](self, coro: Coro[T], *, name: Optional[str] = None, context: Optional[Context] = None):
        async def except_and_log() -> Optional[T]:
            try:
                return await coro
            except Exception as e:
                logger.exception(f"exception in coro {coro}: {repr(e)}")
        return super().create_task(except_and_log(), name=name, context=context)

def only_ok[R](r: Result[R]) -> bool:
    return r.is_ok()

@functools.lru_cache(maxsize=1024) # noqa: CRS102, caching allocation rather than computation
def bytes_to_uuid(u: bytes) -> uuid.UUID:
    return uuid.UUID(u.decode())
