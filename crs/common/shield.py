from contextvars import Context
from typing import Any, AsyncIterator, Coroutine, Optional
import asyncio
import contextlib

type Coro[R] = Coroutine[Any, Any, R]

class _SoloTaskGroup(asyncio.TaskGroup):
    """
    Helper class for SoloTaskGroup
    """
    def __init__(self):
        super().__init__()
        self._creates = 0

    def create_task[T](self, coro: Coro[T], *, name: Optional[str] = None, context: Optional[Context] = None):
        assert self._creates == 0
        self._creates += 1
        return super().create_task(coro, name=name, context=context)

@contextlib.asynccontextmanager
async def SoloTaskGroup() -> AsyncIterator[_SoloTaskGroup]:
    """
    Creates a TaskGroup meant to wrap a single task. Creating multiple tasks on this
    group will fail an assertion.

    If the single task raises an exception, it will be ungrouped from the ExceptionGroup.
    This allows creating interfaces which act like this TaskGroup doesn't exist.
    """
    try:
        async with _SoloTaskGroup() as tg:
            yield tg
    except* Exception as group:
        # the same exception can be raised multiple times in the group
        # e.g. from an `await` in the body, and from the TaskGroup exiting
        # if this happens, ungroup it
        if len(set(id(e) for e in group.exceptions)) == 1:
            raise group.exceptions[0] from group # noqa: ASYNC123; we preserve traceback and cause
        # otherwise, re-raise the group
        raise

async def shield_and_wait[T](coro: Coro[T]) -> T:
    async with SoloTaskGroup() as tg:
        task = tg.create_task(coro, name=f"shield_and_wait({coro!r})")
        # NOTE: `task` can still get cancelled (e.g. during process shutdown)
        while not task.done():
            try:
                _ = await asyncio.shield(task)
            except asyncio.CancelledError:
                pass
        cur = asyncio.current_task()
        if cur and cur.cancelling() > 0:
            raise asyncio.CancelledError()
        # task is done, this can't yield
        return await task

@contextlib.asynccontextmanager
async def finalize(coro: Coro[None]):
    try:
        yield
    finally:
        await shield_and_wait(coro) # noqa: ASYNC102; shield_and_wait behaves like a CancelScope(shield=True)
