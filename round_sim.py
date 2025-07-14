import aiohttp
import asyncio
import argparse
import functools
import json
import re
import yaml

from datetime import datetime, timezone, timedelta
from pathlib import Path
from pydantic import BaseModel, TypeAdapter, field_validator
from typing import Any

from crs.task_server.models import Task, SARIFBroadcast

from crs_rust import logger

JSON_HEADERS = {"Content-Type": "application/json"}

def parse_duration(value: str) -> timedelta:
    pattern = re.compile(r'(?:(?P<hours>\d+)h)?(?:(?P<minutes>\d+)m)?(?:(?P<seconds>\d+)s)?')
    match = pattern.fullmatch(value.strip())
    if not match:
        raise ValueError(f"Invalid duration format: {value}")
    parts = {k: int(v) if v is not None else 0 for k, v in match.groupdict().items()}
    return timedelta(hours=parts["hours"], minutes=parts["minutes"], seconds=parts["seconds"])

class ScheduleItem[T: BaseModel](BaseModel):
    model: type[T]
    path: Path

    @functools.cached_property
    def data(self) -> T:
        content = self.path.read_text()
        raw = json.loads(content)
        return self.model(**raw)

class ScheduleSARIF(ScheduleItem[SARIFBroadcast]):
    model: type[SARIFBroadcast] = SARIFBroadcast
    path: Path
    delay: timedelta

    @field_validator("delay", mode="before")
    @classmethod
    def convert_time(cls, v: str | timedelta):
        if isinstance(v, timedelta):
            return v
        return parse_duration(v)

class ScheduleTask(ScheduleItem[Task]):
    model: type[Task] = Task
    path: Path
    start: timedelta
    duration: timedelta
    sarifs: list[ScheduleSARIF] = []

    @field_validator("start", "duration", mode="before")
    @classmethod
    def convert_time(cls, v: str | timedelta):
        if isinstance(v, timedelta):
            return v
        return parse_duration(v)

Schedule = list[ScheduleTask]

def to_api_timestamp(time: datetime):
    return int(time.timestamp() * 1000)

async def main(schedule_path: Path, task_server: str = 'http://localhost:1324', speed: float = 1.0):
    schedule_raw: list[Any] = yaml.safe_load(schedule_path.read_text()) or []
    schedule = TypeAdapter(Schedule).validate_python(schedule_raw)

    if not schedule:
        logger.warning("empty schedule provided, exiting early")
        return

    # build the messages we need to send
    now = datetime.now(timezone.utc)
    msgs: list[Task | SARIFBroadcast] = []
    for t in schedule:
        details = [
            d.model_copy(update={"deadline": to_api_timestamp(now + (t.start + t.duration) / speed)})
            for d in t.data.tasks
        ]
        msgs.append(t.data.model_copy(update={"message_time": to_api_timestamp(now + t.start / speed), "tasks": details}))
        for s in t.sarifs:
            msgs.append(s.data.model_copy(update={"message_time": to_api_timestamp(now + (t.start + s.delay) / speed)}))

    # sort them by broadcast time
    msgs.sort(key=lambda t: t.message_time)

    for msg in msgs:
        delay = msg.message_time//1000 - datetime.now(timezone.utc).timestamp()
        if delay > 0:
            logger.info(f"waiting {delay} seconds before sending next task or broadcast...")
        await asyncio.sleep(delay)
        if isinstance(msg, Task):
            logger.info(f"Sending task: {msg.message_id=} {len(msg.tasks)=}")
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{task_server}/v1/task/", data=msg.model_dump_json(), headers=JSON_HEADERS) as res:
                    resp = await res.text()
                    if not res.ok:
                        logger.warning(f"Unexpected HTTP response: {res.status} - {resp}")
        else:
            logger.info(f"Sending sarif: {msg.message_id=} {len(msg.broadcasts)=}")
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{task_server}/v1/sarif/", data=msg.model_dump_json(), headers=JSON_HEADERS) as res:
                    resp = await res.text()
                    if not res.ok:
                        logger.warning(f"Unexpected HTTP response: {res.status} - {resp}")

    # wait until the last task expires
    final_deadline = max((t.start + t.duration) / speed for t in schedule)
    final_delta = (now + final_deadline) - datetime.now(timezone.utc)
    await asyncio.sleep(final_delta.total_seconds())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process tasks and optionally generate output.")
    _ = parser.add_argument('--schedule', required=True, help='Path to task schedule yaml file')
    _ = parser.add_argument('--task-server', type=str, default='http://localhost:1324', help='Where to post the tasks')
    _ = parser.add_argument('--speed', type=float, default=1.0, help='Rate to run the schedule at')
    args = parser.parse_args()
    asyncio.run(main(
        schedule_path=Path(args.schedule),
        task_server=args.task_server,
        speed=args.speed
    ))
