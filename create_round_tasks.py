import asyncio
import argparse
import json
import os

from asyncio.subprocess import PIPE
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from uuid import uuid4, UUID
from typing import Optional

from crs.task_server.models import Task, TaskDetail, SourceDetail, SARIFBroadcast, SARIFBroadcastDetail
from crs.common import process, utils

from crs_rust import logger

JSON_HEADERS = {"Content-Type": "application/json"}

def getenv(name: str):
    res = os.getenv(name)
    if not res:
        raise Exception(f"Must set {name} to use this script")
    return res

async def upload_blob(artifact: Path) -> str:
    CONTAINER_NAME = getenv("CONTAINER_NAME")
    STORAGE_ACCOUNT = getenv("STORAGE_ACCOUNT")
    STORAGE_KEY = getenv("STORAGE_KEY")
    CONNECTION_STRING = getenv("CONNECTION_STRING")

    blob_name = artifact.name
    logger.info(f"Uploading {blob_name}...")
    async with process.scope() as scope:
        proc = await scope.exec(*[
            "az", "storage", "blob", "upload",
            "--container-name", CONTAINER_NAME,
            "--account-name", STORAGE_ACCOUNT,
            "--file", artifact.as_posix(),
            "--name", blob_name,
            "--sas-token", STORAGE_KEY,
        ], stdout=PIPE, stderr=PIPE)
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            if b"already exists" in stderr:
                logger.info(f"blob {blob_name} already exists")
            else:
                raise Exception(f"Error uploading blob: {stderr}")

        proc = await scope.exec(*[
            "az", "storage", "blob", "generate-sas",
            "--account-name", STORAGE_ACCOUNT,
            "--container-name", CONTAINER_NAME,
            "--name", blob_name,
            "--permissions", "r",
            "--expiry", "2100-01-01T00:00:00Z",
            "--output", "tsv",
            "--connection-string", CONNECTION_STRING,
            "--full-uri"
        ], stdout=PIPE, stderr=PIPE)
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise Exception(f"Error generating sas: {stderr}")
        return stdout.decode().strip()

async def generate_tasks(
    challenge_tasks: Path,
    tasks_out: Path,
    sarifs_path: Optional[Path] = None,
    skip_upload: bool = False
):
    sources = challenge_tasks / "sources"
    if skip_upload:
        logger.info("skipping blob upload, will use file paths")
        blob_urls = {s.name: f"file://{s.absolute().as_posix()}" for s in sources.iterdir()}
    else:
        logger.info("uploading blobs...")
        blob_tasks: dict[str, asyncio.Task[str]] = {}
        async with asyncio.TaskGroup() as tg:
            for source in sources.iterdir():
                blob_tasks[source.name] = tg.create_task(upload_blob(source))
        blob_urls = await utils.gather_dict(blob_tasks)

    sarifs: defaultdict[UUID, list[SARIFBroadcastDetail]] = defaultdict(list[SARIFBroadcastDetail])
    if sarifs_path is not None:
        for s in json.loads(sarifs_path.read_bytes()):
            s = SARIFBroadcastDetail(**s)
            sarifs[s.task_id].append(s)
    else:
        logger.warning(f"No --sarifs provided, not sending SARIF reports")

    raw_tasks = json.loads((challenge_tasks / "tasks.json").read_bytes())
    tasks: dict[str, Task | SARIFBroadcast] = {}
    now = datetime.now(timezone.utc)

    for t in raw_tasks:
        details: list[TaskDetail] = []
        message_time = now
        duration = timedelta(days=365)
        details.append(TaskDetail(
            deadline=int((message_time + duration).timestamp())  * 1000,
            focus=t["focus"],
            harnesses_included=t["harnesses_included"],
            metadata={},
            project_name=t["project_name"],
            source=[SourceDetail(url=blob_urls[s["url"]], type=s["type"], sha256=s["sha256"]) for s in t["source"]],
            task_id=t["id"],
            type=t["type"],
        ))
        name = f"{t['project_name']}_{t['type']}_{t['id'][-8:]}"
        tasks[name] = Task(
            message_id = uuid4(),
            message_time = int(message_time.timestamp() * 1000),
            tasks=details
        )
        broadcasts: list[SARIFBroadcastDetail] = []
        for t in details:
            broadcasts.extend(sarifs[t.task_id])
        if broadcasts:
            tasks[f"{name}_sarifs"] = SARIFBroadcast(
                broadcasts=broadcasts,
                message_id=uuid4(),
                message_time=int(now.timestamp() * 1000)
            )


    tasks_out.mkdir(exist_ok=True)
    for name, msg in tasks.items():
        path = (tasks_out / f"{name}.json")
        logger.info(f"writing task {path=}")
        _ = path.write_text(msg.model_dump_json())

async def main(
    challenge_tasks: Path,
    tasks_out: Path,
    sarifs: Optional[Path] = None,
    skip_upload: bool = False,
):
    if tasks_out.exists():
        logger.info(f"skipping task generation because {tasks_out} already exists")
    else:
        logger.info("generating tasks...")
        await generate_tasks(challenge_tasks, tasks_out, sarifs, skip_upload)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process tasks and optionally generate output.")

    _ = parser.add_argument('--challenge-tasks', required=True, help='Path to input challenge task dir')
    _ = parser.add_argument('--tasks-out', required=True, help='Path to output tasks')
    _ = parser.add_argument('--sarifs', help='Path to sarifs json if desired')
    _ = parser.add_argument('--skip-upload', action='store_true', help='Skip uploading the source blobs, use file URLs')

    args = parser.parse_args()

    asyncio.run(main(
        challenge_tasks=Path(args.challenge_tasks),
        tasks_out=Path(args.tasks_out),
        sarifs=Path(args.sarifs) if args.sarifs else None,
        skip_upload=args.skip_upload,
    ))