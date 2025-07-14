import asyncio
import threading
import time

from crs.config import metrics

thread_latency_diff = metrics.create_gauge("thread-latency-diff")
async_latency_diff  = metrics.create_gauge("async-latency-diff")

SLEEP = 0.250

def thread_latency_monitor():
    while True:
        start = time.perf_counter()
        time.sleep(SLEEP)
        elapsed = time.perf_counter() - start
        thread_latency_diff.set(elapsed - SLEEP)

async def async_latency_monitor():
    threading.Thread(target=thread_latency_monitor, daemon=True, name="thread_latency_monitor").start()
    while True:
        start = time.perf_counter()
        await asyncio.sleep(SLEEP)
        elapsed = time.perf_counter() - start
        async_latency_diff.set(elapsed - SLEEP)
