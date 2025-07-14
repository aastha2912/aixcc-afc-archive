import ast
import functools
from typing import Generator, Type, Any, Self
from abc import abstractmethod

class ForbiddenCallChecker:
    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @property
    @abstractmethod
    def rule(self) -> str:
        ...

    @property
    @abstractmethod
    def extra(self) -> str:
        ...

    @property
    @abstractmethod
    def version(self) -> str:
        ...

    @property
    @abstractmethod
    def forbidden(self) -> set[str]:
        ...

    @functools.cached_property
    def forbidden_split(self) -> set[tuple[str, ...]]:
        return set(tuple(f.split('.')) for f in self.forbidden)

    def __init__(self, tree: ast.AST):
        self.tree = tree

    def run(self) -> Generator[tuple[int, int, str, Type[Self]], Any, None]:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ImportFrom):
                yield from self.check_import_from(node)
            elif isinstance(node, ast.Call):
                yield from self.check_func(node.func, node.lineno, node.col_offset)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                for dec in node.decorator_list:
                    # decorator without args: @foo.bar
                    yield from self.check_func(dec, dec.lineno, dec.col_offset)

    def check_import_from(self, imp: ast.ImportFrom):
        if imp.module is None:
            return
        split = tuple(imp.module.split('.'))
        names = [n.name for n in imp.names]
        for f in self.forbidden_split:
            if len(f) <= len(split):
                continue
            prefix, ban = f[:len(split)], f[len(split)]
            if prefix == split and ban in names:
                yield (
                    imp.lineno,
                    imp.col_offset,
                    f"{self.rule}: Cannot import {ban} from {imp.module} because the linter requires fully qualified names.",
                    type(self)
                )
                break

    def check_func(self, func: ast.expr, lineno: int, col_offset: int):
        full_call = self._get_full_name(func)
        if full_call in self.forbidden:
            yield (
                lineno,
                col_offset,
                f"{self.rule}: Calling {full_call} is forbidden. {self.extra}",
                type(self),
            )

    def _get_full_name(self, node: ast.expr):
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.insert(0, node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.insert(0, node.id)
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                parts.insert(0, func.attr)
                if isinstance(func.value, ast.Name):
                    parts.insert(0, func.value.id)
            elif isinstance(func, ast.Name):
                parts.insert(0, func.id)
        return ".".join(parts)

# TODO: allow this if it's shielded?
class AsyncioSubprocessChecker(ForbiddenCallChecker):
    @property
    def name(self): return 'no-asyncio-subprocess'
    @property
    def rule(self): return 'CRS100'
    @property
    def extra(self):
        return (
            'https://github.com/python/cpython/issues/103847 makes this function '
            'dangerous to use unshielded. Use crs.common.process.ProcessScope.exec '
            'instead.'
        )
    @property
    def version(self): return '0.1.0'
    @property
    def forbidden(self):
        return {"asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell"}

class AsyncioCreateTaskChecker(ForbiddenCallChecker):
    @property
    def name(self): return 'no-asyncio-create-task'
    @property
    def rule(self): return 'CRS101'
    @property
    def extra(self): return 'Use structured concurrency with asyncio.TaskGroup.create_task.'
    @property
    def version(self): return '0.1.0'
    @property
    def forbidden(self):
        return {"asyncio.create_task"}

class FunctoolsCacheChecker(ForbiddenCallChecker):
    @property
    def name(self): return 'no-functools-cache'
    @property
    def rule(self): return 'CRS102'
    @property
    def extra(self): return 'Use crs.common.alru.alru_cache or crs.common.utils.cached_property instead.'
    @property
    def version(self): return '0.1.0'
    @property
    def forbidden(self):
        return {"functools.cached_property", "functools.cache", "functools.lru_cache"}

class TaskGroupCreateTaskNameChecker:
    """Flake8 checker that enforces passing *name=* when using TaskGroup.create_task."""

    name = "require-taskgroup-create-task-name"
    rule = "CRS103"
    version = "0.1.0"

    _message = (
        "CRS103: TaskGroup.create_task must be called with a \"name=...\" keyword "
        "argument to aid debugging and observability."
    )

    def __init__(self, tree: ast.AST):
        self.tree = tree

    # The flake8 plugin protocol expects an attribute version (str) and a run() generator
    # yielding (lineno, col_offset, message, type)

    def run(self):
        for node in ast.walk(self.tree):
            # Interested only in call expressions
            if not isinstance(node, ast.Call):
                continue

            func = node.func

            # We consider any attribute access *.create_task. This captures typical
            # usage of structured concurrency::
            #
            #     async with TaskGroup() as tg:
            #         tg.create_task(coro(), name="worker")
            #
            # While we cannot *statically* guarantee the object is a TaskGroup
            # instance, this heuristic is sufficient in practice and avoids
            # false negatives.
            if isinstance(func, ast.Attribute) and func.attr == "create_task":
                # The TaskGroup.create_task signature is
                #   create_task(coro, *, name=None, context=None)
                # so *name* must be supplied by keyword. A simple positional
                # argument check is therefore enough.
                if not any(kw.arg == "name" for kw in node.keywords):
                    yield (
                        node.lineno,
                        node.col_offset,
                        self._message,
                        type(self),
                    )