# completely fair scheduler, inspired by linux/kernel/sched/fair.c

from collections.abc import Hashable
from dataclasses import dataclass
from typing import Optional, Self
import time

@dataclass(slots=True)
class ScheduleTask[K]:
    key: K

    last_tick: int = 0
    vruntime: int = 0
    running: int = 0
    waiting: int = 0

    def tick(self, now: int) -> None:
        self.vruntime += (now - self.last_tick) * self.running
        self.last_tick = now

    def __lt__(self, other: Self) -> bool:
        return self.vruntime < other.vruntime

@dataclass
class Scheduler[K: Hashable]:
    tasks: dict[K, ScheduleTask[K]]
    running: set[K]
    waiting: set[K]
    queue: list[ScheduleTask[K]]

    vmin: int
    quantum: int
    tickrate: int
    last_tick: int

    def __init__(self) -> None:
        self.tasks = {}
        self.running = set()
        self.waiting = set()
        self.queue = []

        self.vmin = 0
        # tasks are loaned quantum=10s of runtime when they start
        #  to be returned on task completion
        self.quantum = int(10e9)
        self.wakeup  = int(1e9)

        self.tickrate = int(0.1e9)
        self.last_tick = 0

    # add a task and mark it as waiting for another slot
    def add(self, key: K) -> None:
        if (task := self.tasks.get(key)) is None:
            task = ScheduleTask(key)
            self.tasks[key] = task
        task.waiting += 1
        if task.waiting == 1:
            self.waiting.add(key)
            self.queue.append(task)

    # remove a waiting slot from a task
    def remove(self, key: K) -> None:
        if (task := self.tasks.get(key)) is None:
            raise KeyError(f"removed non-existent task: {key}")
        if task.waiting <= 0:
            raise ValueError(f"removed non-waiting task: {key}")
        task.waiting -= 1
        # don't bother removing it from self.queue, we'll just not schedule it if we ever pop it
        if task.waiting == 0:
            self.waiting.discard(key)

    # remove all waiting slots for a task
    def discard(self, key: K) -> None:
        if (task := self.tasks.get(key)) is None:
            return
        task.waiting = 0
        self.waiting.discard(key)

    # mark one slot of a task as done running
    def finish(self, key: K) -> None:
        if (task := self.tasks.get(key)) is None:
            raise KeyError(f"finished non-existent task: {key}")
        if task.running <= 0:
            raise ValueError(f"finished non-running task: {key}")
        now = time.perf_counter_ns()
        task.tick(now)
        task.running -= 1
        task.vruntime = max(0, task.vruntime - self.quantum) # refund
        if task.running == 0:
            self.running.discard(key)

    # request a task to run
    def schedule(self) -> Optional[K]:
        now = time.perf_counter_ns()
        self.tick(now)
        # this may take multiple iterations, because a task may be lazily removed from the queue
        while self.queue:
            task = self.queue[-1]
            # print(task.key, task.running, task.vruntime)
            if task.waiting == 0:
                _ = self.queue.pop()
                continue
            task.waiting -= 1
            if task.waiting == 0:
                _ = self.queue.pop()
                self.waiting.discard(task.key)
            # reset task metrics if it was inactive
            if task.running == 0:
                task.last_tick = now
                task.vruntime = max(self.vmin - self.wakeup, task.vruntime)
            else:
                # need to tick before adjusting task.running up/down
                task.tick(now)
            task.running += 1
            task.vruntime += self.quantum # credit
            self.running.add(task.key)
            return task.key
        return None

    # run task accounting and re-sort the queue
    def tick(self, now: Optional[int]=None) -> None:
        if now is None:
            now = time.perf_counter_ns()
        delta = now - self.last_tick
        if delta > self.tickrate:
            if delta > self.tickrate * 2:
                self.last_tick = now
            else:
                self.last_tick += self.tickrate

            if self.running:
                first_key = next(iter(self.running))
                vmin = self.tasks[first_key].vruntime
                for key in self.running:
                    task = self.tasks[key]
                    task.tick(now)
                    vmin = min(vmin, task.vruntime)
                self.vmin = max(self.vmin, vmin)
        self.queue.sort(reverse=True)

if __name__ == "__main__":
    from tqdm import tqdm
    sched = Scheduler[str]()
    n_tasks = 150
    n_jobs = 100_000
    for taskn in tqdm(range(n_tasks), desc="adding"):
        for jobn in range(n_jobs):
            sched.add(f"task{taskn}")
    jobs: list[str] = []
    with tqdm("schedule", total=n_tasks * n_jobs) as pbar:
        while True:
            task = sched.schedule()
            # print(task)
            if task is None:
                break
            jobs.append(task)
            _ = pbar.update(1)
    for job in jobs:
        sched.finish(job)
    assert len(sched.running) == 0
    assert len(sched.waiting) == 0
    assert len(sched.queue) == 0
