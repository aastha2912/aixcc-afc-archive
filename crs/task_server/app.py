import os
import secrets

from typing import Optional
from uuid import UUID

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from crs.app.submitter import Submitter

from crs_rust import logger

security = HTTPBasic()

USERNAME = os.environ.get("API_KEY_ID") or ""
PASSWORD = os.environ.get("API_KEY_TOKEN") or ""

if USERNAME == "":
    logger.warning("No basic auth credentials set. If you intend for basic auth to work, set API_KEY_ID and API_KEY_TOKEN")

def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    is_correct_username = secrets.compare_digest(credentials.username, USERNAME)
    is_correct_password = secrets.compare_digest(credentials.password, PASSWORD)
    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )

from .models import SARIFBroadcast, Status, Task
from .db import TaskDB, MissingStatusException

app = FastAPI(
    contact={},
    title='Theori CRS API',
    version='1.4',
    servers=[{'url': '/'}],
    dependencies=[Depends(verify_credentials)] if USERNAME else []
)

db = TaskDB()
submitter = Submitter()

async def update_status(status: Status):
    status.ready = await submitter.ping()
    return status

@app.delete('/status/', response_model=str, tags=['status'])
async def delete_status_() -> str:
    """
    Reset status stats
    """
    _ = await db.reset_status()
    return "OK"


@app.get('/status/', response_model=Status, tags=['status'])
async def get_status_() -> Status:
    """
    CRS Status
    """
    try:
        return await update_status(await db.get_status())
    except MissingStatusException:
        return await update_status(await db.reset_status())


@app.post('/v1/sarif/', response_model=str, tags=['sarif'])
async def post_v1_sarif_(body: SARIFBroadcast) -> str:
    """
    Submit Sarif Broadcast
    """
    await db.put_sarifs(body)
    return "OK"


@app.delete('/v1/task/', response_model=str, tags=['task'])
async def delete_v1_task_() -> str:
    """
    Cancel Tasks
    """
    await db.cancel_all()
    return "OK"


@app.post(
    '/v1/task/', response_model=None, responses={'202': {'model': str}}, tags=['task']
)
async def post_v1_task_(body: Task) -> Optional[str]:
    """
    Submit Task
    """
    await db.put_tasks(body)
    return "OK"


@app.delete('/v1/task/{task_id}/', response_model=str, tags=['task'])
async def delete_v1_task_task_id_(task_id: UUID) -> str:
    """
    Cancel Task
    """
    await db.cancel_task(task_id)
    return "OK"
