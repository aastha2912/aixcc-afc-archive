import asyncio
from contextlib import AsyncExitStack
from contextvars import ContextVar
from typing import TYPE_CHECKING, Optional
if TYPE_CHECKING:
    from crs.app.app import CRS
from crs.common.workdb_meta import cur_job_task

running_crs: ContextVar[Optional['CRS']] = ContextVar("running_crs", default=None)

_exit_stack: Optional[AsyncExitStack] = None

async def run_global_exit_stack():
    global _exit_stack
    assert _exit_stack is None
    async with AsyncExitStack() as stack:
        _exit_stack = stack
        try:
            while True:
                await asyncio.sleep(float('inf'))
        finally:
            _exit_stack = None

def cur_task_exit_stack() -> Optional[AsyncExitStack]:
    if (crs := running_crs.get()) and (task := cur_job_task.get()):
        return crs.exit_stacks.get(task)
    if _exit_stack:
        return _exit_stack