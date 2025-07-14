from dataclasses import dataclass, field
from typing import cast, Any, AsyncIterator, Callable, Concatenate, Coroutine, Self, Optional, Type, overload
import asyncio
import contextlib
import functools
import time

from crs.common.types import Err, CRSError

@dataclass(slots=True)
class LockState:
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    count: int = 0

class LockGroup:
    locks: dict[Any, LockState]

    def __init__(self):
        self.locks = dict()

    @contextlib.asynccontextmanager
    async def lock(self, key: Any) -> AsyncIterator[None]:
        if (state := self.locks.get(key)) is None:
            state = self.locks[key] = LockState()

        state.count += 1
        try:
            async with state.lock:
                yield
        finally:
            state.count -= 1
            if state.count == 0:
                del self.locks[key]

    def __contains__(self, key: Any) -> bool:
        return key in self.locks

class AlruCacheKey:
    __slots__ = ["key", "hash_value"]

    key: Any
    hash_value: int

    def __init__(self, key: Any):
        self.key = key
        self.hash_value = hash(key)

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, AlruCacheKey) and self.key == other.key

    def __hash__(self) -> int:
        return self.hash_value

    def __repr__(self) -> str:
        return repr(self.key)

@dataclass(slots=True)
class AlruCacheEntry[T]:
    key: Any
    value: T
    ts: float

    def __lt__(self, other: Self) -> bool:
        return self.ts < other.ts

@dataclass(slots=True)
class AlruCacheStats:
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    cancellations: int = 0
    cursize: int = 0
    maxsize: Optional[int] = None

def remake_err[R](value: R) -> R:
    match value:
        case Err(CRSError() as e):
            return cast(R, Err(CRSError(e.error, e.extra))) # recreate a stack trace
        case _:
            return value

type AsyncLruFn[**P, R] = Callable[P, Coroutine[Any, Any, R]]

def _alru_cache[**P, R](*, maxsize: Optional[int] = 128, filter: Optional[Callable[[R], bool]] = None) -> Callable[[AsyncLruFn[P, R]], AsyncLruFn[P, R]]:
    keyword_mark = (object(),)
    def make_key(args: tuple[Any, ...], kwargs: dict[str, Any]) -> AlruCacheKey:
        return AlruCacheKey(args + keyword_mark + tuple((k, v) for k, v in kwargs.items()))

    def alru_cache_inner(fn: AsyncLruFn[P, R]) -> AsyncLruFn[P, R]:
        cache: dict[AlruCacheKey, AlruCacheEntry[R]] = {}
        locks = LockGroup()
        stats = AlruCacheStats(maxsize=maxsize)

        @functools.wraps(fn)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            key = make_key(args, kwargs)
            # cache hit 1 (NOTE: duplicated with logic below)
            if (entry := cache.get(key)) is not None:
                stats.hits += 1
                entry.ts = time.perf_counter()
                return remake_err(entry.value)

            async with locks.lock(key):
                # cache hit 2 (NOTE: duplicated with logic above)
                if (entry := cache.get(key)) is not None:
                    stats.hits += 1
                    entry.ts = time.perf_counter()
                    return remake_err(entry.value)

                # cache miss
                stats.misses += 1
                try:
                    cache_value = value = await fn(*args, **kwargs)
                except asyncio.CancelledError:
                    stats.cancellations += 1
                    raise
                if not filter or filter(value):
                    match value:
                        case Err(CRSError() as e):
                            cache_value = cast(R, Err(CRSError(e.error, e.extra, include_traceback=False)))
                            value = cast(R, value)
                        case _:
                            pass
                    entry = AlruCacheEntry(
                        key=key,
                        value=cache_value,
                        ts=time.perf_counter(),
                    )
                    cache[key] = entry

                # cache evict
                extras = 0 if maxsize is None else len(cache) - maxsize
                if extras > 0:
                    for item in sorted(cache.values()):
                        if item.key in locks:
                            continue
                        if extras <= 0:
                            break
                        stats.evictions += 1
                        del cache[item.key]
                        extras -= 1
                stats.cursize = len(cache)
                return value

        setattr(wrapper, "__alru_stats__", stats)
        return wrapper

    return alru_cache_inner


type AsyncSelfLruFn[S, **P, R] = Callable[Concatenate[S, P], Coroutine[Any, Any, R]]
@overload
def alru_cache[S, **P, R](*, maxsize: Optional[int] = 128, filter: None = None) -> Callable[[AsyncLruFn[P, R]], AsyncLruFn[P, R]]:
    ...
@overload
def alru_cache[S, **P, R](*, maxsize: Optional[int] = 128, filter: Callable[[R], bool]) -> Callable[[AsyncLruFn[P, R]], AsyncLruFn[P, R]]:
    ...
def alru_cache[S, **P, R](*, maxsize: Optional[int] = 128, filter: Optional[Callable[[R], bool]] = None) -> Callable[[AsyncLruFn[P, R]], AsyncLruFn[P, R]]:
    class AlruCacheDescriptor:
        def __init__(self, fn: AsyncLruFn[P, R]):
            self.fn = fn
            self.name = fn.__name__
            _ = functools.update_wrapper(self, fn)
            setattr(self, "__alru_stats__", getattr(self.__call__, "__alru_stats__"))

        def __set_name__(self, owner: Type[S], name: str):
            self.name = name

        def __get__(self, obj: Optional[S], objtype: Optional[Type[S]]=None):
            if obj is None:
                return self
            @_alru_cache(maxsize=maxsize, filter=filter)
            @functools.wraps(self.fn)
            async def wrapper(*args: P.args, **kwargs: P.kwargs):
                fn = cast(AsyncSelfLruFn[S, P, R], self.fn)
                return await fn(obj, *args, **kwargs)
            setattr(obj, self.name, wrapper)
            # don't serialize the wrapper
            setattr(obj, '_jsonpickle_exclude', getattr(obj, '_jsonpickle_exclude', set[str]()) | {self.name})
            return wrapper

        @_alru_cache(maxsize=maxsize, filter=filter)
        async def __call__(self, *args: P.args, **kwargs: P.kwargs) -> R:
            return await self.fn(*args, **kwargs)

    return AlruCacheDescriptor

async_once = alru_cache(maxsize=None)
