from contextvars import ContextVar
from crs.common.types import Priority
from typing import Optional
from uuid import UUID

cur_job_id: ContextVar[int] = ContextVar('cur_job_id', default=0)
cur_job_priority: ContextVar[float] = ContextVar('cur_priority', default=Priority.LOWEST)
cur_job_task: ContextVar[Optional[UUID]] = ContextVar('cur_job_task', default=None)
cur_job_worktype: ContextVar[int] = ContextVar('cur_job_worktype', default=0)
