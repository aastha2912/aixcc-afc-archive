import pprint
from typing import (
    IO,
    Any,
    Callable,
    Sequence,
    cast,
)

DispatchHandler = Callable[
    [
        "RLEPrettyPrinter",  # self
        Any,                 # obj
        IO[str],             # stream
        int,                 # indent
        int,                 # allowance
        dict[Any, int],      # context
        int,                 # level
    ],
    None,
]

DispatchKey = Callable[[Any], str]
DispatchTable = dict[DispatchKey, DispatchHandler]

class RLEPrettyPrinter(pprint.PrettyPrinter):
    def __init__(
        self,
        *args: Any,
        min_repeat: int = 10,
        max_subseq: int = 10,
        **kwargs: Any,
    ):
        super().__init__(*args, **kwargs)

        self._min_repeat: int = min_repeat
        self._max_subseq: int = max_subseq
        self._width: int = self._width

        # Record the *original* handlers so we can fall back later
        self._base_handlers: dict[type, DispatchHandler] = {
            t: cast(DispatchHandler, self._dispatch[t.__repr__])  # type: ignore[attr-defined]
            for t in (str, bytes, list, tuple)
        }

        # Give the dispatch table a precise type and then patch it
        self._dispatch = cast(DispatchTable, self._dispatch.copy())  # type: ignore[attr-defined]
        for t in (str, bytes, list, tuple):
            self._dispatch[t.__repr__] = RLEPrettyPrinter._pprint_rle  # type: ignore[attr-defined]

    def _repr(self, obj: Any, context: dict[Any, int], level: int) -> str:
        return super()._repr(obj, context, level) # type: ignore

    def _longest_run(self, seq: Sequence[Any], pos: int) -> tuple[int, int]:
        n = len(seq)
        best_L = best_K = 0
        for L in range(1, min(self._max_subseq, n - pos) + 1):
            pat = seq[pos : pos + L]
            k = 1
            while (
                pos + L * (k + 1) <= n
                and seq[pos + L * k : pos + L * (k + 1)] == pat
            ):
                k += 1
            if k >= self._min_repeat and k * L > best_K * best_L:
                best_L, best_K = L, k
        return best_L, best_K

    def _compress(
        self,
        seq: Sequence[Any],
        context: dict[Any, int],
        level: int,
    ) -> str | None:
        n = len(seq)
        pieces: list[str] = []
        i = seg_start = 0

        def emit(lo: int, hi: int) -> None:
            if lo < hi:
                pieces.append(self._repr(seq[lo:hi], context, level))

        while i < n:
            L, K = self._longest_run(seq, i)
            if K:  # we found a run worth compressing
                emit(seg_start, i)
                run_repr = self._repr(seq[i : i + L], context, level)
                if '\n' in run_repr: run_repr = f"({run_repr})"
                pieces.append(f"{run_repr}*{K}")
                i += L * K
                seg_start = i
            else:
                i += 1

        if not pieces:           # nothing compressed at all
            return None

        emit(seg_start, n)
        joined = " + ".join(pieces)
        return joined if len(pieces) == 1 else f"({joined})"

    def _reshape(
        self,
        compressed: str,
        indent: int,
        allowance: int
    ):
        width = self._width
        if len(compressed) + indent + allowance > width:
            limit = width - indent - allowance
            parts = compressed.split(" + ")
            lines: list[str] = []
            current = parts[0]
            for part in parts[1:]:
                if len(current) + 3 + len(part) <= limit:
                    current += " + " + part
                else:
                    lines.append(current)
                    current = part
            lines.append(current)
            joiner = " +\n" + " " * indent
            compressed = joiner.join(lines)
        return compressed

    def _pprint_rle(
        self,
        obj: Sequence[Any],
        stream: IO[str],
        indent: int,
        allowance: int,
        context: dict[int, int],
        level: int,
    ) -> None:
        compressed = self._compress(obj, context, level)
        if compressed is None:
            # fall back to the standard handler
            return self._base_handlers[type(obj)](self, obj, stream, indent, allowance, context, level)
        _ = stream.write(self._reshape(compressed, indent, allowance))