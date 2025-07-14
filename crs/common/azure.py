from asyncio.subprocess import DEVNULL, PIPE, STDOUT
from datetime import datetime, timedelta, UTC
from typing import Optional
import asyncio
import time

from crs import config
from crs.config import metrics
from crs.common import process
from crs.common.utils import requireable, require
from crs.common.types import Result, Ok, Err, CRSError

lock = asyncio.Lock()
test_lock = asyncio.Lock()
last_expiry: Optional[datetime] = None
last_acr_refresh: Optional[float] = None
last_acr_test: Optional[float] = None

azure_expiry_metric = metrics.create_gauge("azure-expiry")
azure_login_metric = metrics.create_counter("azure-login")
acr_login_metric = metrics.create_counter("acr-login")

async def azure_token_expiry() -> Optional[datetime]:
    try:
        async with process.scope(timeout=15) as scope:
            proc = await scope.exec("az", "account", "get-access-token", "--query", "expires_on", "-o", "tsv", stdout=PIPE, stderr=DEVNULL)
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return None
            expiry = datetime.fromtimestamp(int(stdout), tz=UTC)
            return expiry
    except TimeoutError:
        return None

@requireable
async def ensure_azure_login() -> Result[bool]:
    global last_expiry
    if not config.REGISTRY_NAME:
        return Ok(False)

    azure_login_metric.add(1, {"stage": "check"})
    utcnow = datetime.now(UTC)
    cliff = utcnow + timedelta(hours=1)
    last = last_expiry
    if last is not None and last > cliff:
        azure_login_metric.add(1, {"stage": "skip-cached-grace"})
        return Ok(False)

    token_expiry = await azure_token_expiry()
    if token_expiry is not None:
        azure_expiry_metric.set((token_expiry - utcnow).total_seconds())

    if token_expiry is not None and token_expiry > cliff:
        azure_login_metric.add(1, {"stage": "skip-checked-grace"})
        last_expiry = token_expiry
        return Ok(False)

    azure_login_metric.add(1, {"stage": "login"})
    try:
        async with process.scope(timeout=30) as scope:
            async with lock:
                proc = await scope.exec("az", "login", "--identity", stdout=PIPE, stderr=STDOUT)
                output, _ = await proc.communicate()
            if proc.returncode != 0:
                azure_login_metric.add(1, {"stage": "error"})
                return Err(CRSError(f"az login failed: {output}"))

    except TimeoutError:
        azure_login_metric.add(1, {"stage": "timeout"})
        return Err(CRSError(f"az login --identity timed out"))

    # if True, our token was expiring soon
    acr_login_metric.add(1, {"stage": "success"})
    return Ok(token_expiry is not None)

@requireable
async def ensure_acr_login(*, force: bool=False) -> Result[None]:
    global last_acr_refresh
    global last_acr_test
    if not config.REGISTRY_NAME:
        return Ok(None)

    _ = require(await ensure_azure_login())
    try:
        acr_login_metric.add(1, {"stage": "check"})
        pre_lock = time.perf_counter()
        async with process.scope(timeout=30) as scope, test_lock:
            now = time.perf_counter()
            recent_refresh = (not last_acr_refresh) or (now - last_acr_refresh < 3600)
            recent_test = last_acr_test and (now - last_acr_test < 30 or last_acr_test > pre_lock)
            if recent_refresh and not force:
                if recent_test:
                    acr_login_metric.add(1, {"stage": "skip-test-recent"})
                    return Ok(None)
                proc = await scope.exec("docker", "manifest", "inspect", f"{config.REGISTRY_DOMAIN}/alpine:latest", stdout=DEVNULL, stderr=DEVNULL)
                if await proc.wait() == 0:
                    acr_login_metric.add(1, {"stage": "skip-login-manifest"})
                    last_acr_test = time.perf_counter()
                    return Ok(None)

        async with process.scope(timeout=30) as scope, lock:
            if last_acr_refresh and last_acr_refresh > pre_lock:
                acr_login_metric.add(1, {"stage": "skip-login-recent"})
                return Ok(None)

            acr_login_metric.add(1, {"stage": "login"})
            proc = await scope.exec("az", "acr", "login", "--name", config.REGISTRY_NAME, stdout=PIPE, stderr=STDOUT)
            output, _ = await proc.communicate()
            if await proc.wait() == 0:
                acr_login_metric.add(1, {"stage": "success"})
                last_acr_refresh = time.perf_counter()
                return Ok(None)
            acr_login_metric.add(1, {"stage": "error"})
            return Err(CRSError(f"az acr login failed: {output}"))

    except TimeoutError:
        acr_login_metric.add(1, {"stage": "timeout"})
        return Err(CRSError("az acr login timed out"))
