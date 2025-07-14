import asyncio
import orjson
import os
import rustworkx
import quicksect

from dataclasses import dataclass
from typing import cast, Optional

from crs.common.path import PathSuffixTree
from crs.common.types import Ok, Err, Result, CRSError

from crs_rust import logger

def shortest_from_sources_dijkstra(
    g: rustworkx.PyDiGraph,
    sources: set[int],
    sink: int,
) -> list[int] | None:
    """
    Return the shortest (fewest-edge) path from *any* node in ``sources``
    to ``sink`` using :pyfunc:`rustworkx.digraph_dijkstra_shortest_paths`.
    Runs one Dijkstra search per source.
    """
    best_path: Optional[list[int]] = None

    for src in sources:
        if src == sink:
            return [sink]
        pathmap = rustworkx.digraph_dijkstra_shortest_paths(
            g,
            src,
            target=sink,
            weight_fn=None,
            default_weight=1,
        )
        if sink not in pathmap:
            continue
        path = pathmap[sink]

        if best_path is None or len(path) < len(best_path):
            best_path = list(iter(path))

    return best_path

# quicksect wrapper for typing
@dataclass
class IntervalMember[D]:
    start: int
    end: int
    data: D
class Interval[D]:
    def add(self, start: int, end: int, dat: D):
        ...
    def search(self, start: int, end: int) -> list[IntervalMember[D]]:
        ...

@dataclass
class Closest:
    harness: int
    input_id: int
    entry: str
    distance: int

@dataclass
class NodeData:
    desc: str
    direct_hits: set[int]
    reachable_hits: set[int]
    frontier: bool
    closest: Optional[Closest]

# TODO: can unreachable lines help us?
class ReachabilityGraph:
    def __init__(self):
        self.graph: rustworkx.PyDiGraph[NodeData] = rustworkx.PyDiGraph()
        self.file_line_lookup: dict[str, Interval[int]] = {}
        self.node_str_to_id: dict[str, int] = {}

    async def initialize_graph(self, json_dat: str, suffix_tree: PathSuffixTree):
        callgraph = await asyncio.to_thread(orjson.loads, json_dat)
        last_lookup = "", ""
        for entry, dat in callgraph.items():
            file, start, end, func = entry.split(":", maxsplit=3)
            # skip dummy stuff about globals or builtin operators
            if end == "-1" or func.startswith("<"):
                continue
            if file not in self.file_line_lookup:
                self.file_line_lookup[file] = cast(Interval[str], quicksect.IntervalTree()) # type: ignore
                if last_lookup[0] == file:
                    self.file_line_lookup[last_lookup[1]] = self.file_line_lookup[file]
                else:
                    match suffix_tree.normalize_path(file):
                        case Ok(short):
                            last_lookup = file, short
                            self.file_line_lookup[short] = self.file_line_lookup[file]
                        case _:
                            pass
            node_id = self.graph.add_node(NodeData(desc=entry, direct_hits=set(), reachable_hits=set(), frontier=False, closest=None))
            self.file_line_lookup[file].add(int(start), max(int(start)+1, int(end)), (node_id))
            self.node_str_to_id[entry] = node_id

        # must do a second pass so we know the numeric node id
        for entry, dat in callgraph.items():
            file, start, end, func = entry.split(":", maxsplit=3)
            # skip dummy stuff about globals or builtin operators
            if end == "-1" or func.startswith("<"):
                continue
            if (entry_id := self.node_str_to_id.get(entry)) is None:
                logger.warning("missing {entry} in graph node list", entry=entry)
                continue
            _ = self.graph.add_edges_from(
                (entry_id, self.node_str_to_id[callee], None) for callee in dat['callees']
                if callee in self.node_str_to_id
            )

    def _node_hit_score(self, node_id: int) -> int:
        score = 0
        queued = set(self.graph.successor_indices(node_id))
        seen: set[int] = set()
        while queued:
            cur = queued.pop()
            if cur in seen:
                continue
            seen.add(cur)
            hit_dat = self.graph[cur]
            if hit_dat.direct_hits:
                # don't count this score, nor recurse and count its children
                continue
            _, start, end, _ = hit_dat.desc.split(":", maxsplit=3)
            score += 1 + (int(end) - int(start))//50
            queued |= set(self.graph.successor_indices(cur))
        return score

    def get_frontier(self) -> list[tuple[NodeData, float]]:
        return [(node, score) for _, node, score in sorted(
            [
                (i,v,self._node_hit_score(i)) for i, v in zip(self.graph.node_indices(), self.graph.nodes()) if v.frontier
            ],
            key=lambda x:x[2],
            reverse=True,
        )]

    def get_node_for_line(self, file: str, line: int) -> Optional[int]:
        if (ivals := self.file_line_lookup.get(file)) is None:
            return None

        if not (matches := sorted(ivals.search(line, line), key=lambda i: i.end-i.start)):
            return None

        return matches[0].data

    def get_info_for_line(self, file: str, line: int) -> Optional[tuple[int, NodeData]]:
        entry = self.get_node_for_line(file, line)
        if not entry:
            logger.debug(f"cannot resolve graph node for {file}:{line}")
            return
        return entry, self.graph[entry]

    def add_new_hits(self, input_id: int, harness_num: int, cov: dict[str, list[int]]) -> bool:
        queued: set[tuple[int, int, int]] = set()

        for file, lines in cov.items():
            normed = os.path.normpath(file)
            for line in lines:
                match self.get_info_for_line(normed, line):
                    case None:
                        continue
                    case entry, node_dat:
                        node_dat.direct_hits.add(harness_num)
                        if not node_dat.closest or node_dat.closest.distance > 0:
                            node_dat.closest = Closest(harness=harness_num, input_id=input_id, entry=node_dat.desc, distance=0)
                        node_dat.frontier = False
                        queued |= {(suc, entry, 1) for suc in self.graph.successor_indices(entry)}

        while queued:
            cur, entry, distance = queued.pop()
            hit_dat = self.graph[cur]
            if harness_num in hit_dat.direct_hits:
                continue
            if distance == 1 and not hit_dat.direct_hits:
                hit_dat.frontier = True
            update_descendants = False
            if harness_num not in hit_dat.reachable_hits:
                hit_dat.reachable_hits.add(harness_num)
                update_descendants = True
            if hit_dat.closest is None or distance < hit_dat.closest.distance:
                hit_dat.closest = Closest(harness=harness_num, input_id=input_id, entry=self.graph[entry].desc, distance=distance)
                update_descendants = True
            if update_descendants:
                queued |= set((x, entry, distance+1) for x in self.graph.successor_indices(cur))
        return True

    def add_new_hit(self, input_id: int, file: str, line: int, harness_num: int) -> bool:
        match self.get_info_for_line(file, line):
            case None:
                return False
            case entry, node_dat:
                pass

        node_dat.direct_hits.add(harness_num)
        if not node_dat.closest or node_dat.closest.distance > 0:
            node_dat.closest = Closest(harness=harness_num, input_id=input_id, entry=node_dat.desc, distance=0)
        node_dat.frontier = False

        queued = {(suc, 1) for suc in self.graph.successor_indices(entry)}
        while queued:
            cur, distance = queued.pop()
            hit_dat = self.graph[cur]
            if harness_num in hit_dat.direct_hits:
                continue
            if distance == 1 and not hit_dat.direct_hits:
                hit_dat.frontier = True
            update_descendants = False
            if harness_num not in hit_dat.reachable_hits:
                hit_dat.reachable_hits.add(harness_num)
                update_descendants = True
            if hit_dat.closest is None or distance < hit_dat.closest.distance:
                hit_dat.closest = Closest(harness=harness_num, input_id=input_id, entry=self.graph[entry].desc, distance=distance)
                update_descendants = True
            if update_descendants:
                queued |= set((x, distance+1) for x in self.graph.successor_indices(cur))
        return True


    async def find_path(self, suffix_tree: PathSuffixTree, sources: list[tuple[str, int]], sink: tuple[str, int]) -> Result[list[tuple[str, str]]]:
        def normalize(path: str, line: int):
            match suffix_tree.normalize_path(path):
                case Ok(norm):
                    return norm, line
                case Err(_):
                    return path, line
        if (dst := self.get_node_for_line(*(normalize(*sink)))) is None:
            return Err(CRSError("could not find dst node"))
        srcs = set([node for src in sources if (node := self.get_node_for_line(*(normalize(*src)))) is not None])
        if len(srcs) == 0:
            return Err(CRSError("no nodes found for sources"))
        elif len(srcs) < len(sources):
            logger.warning("could not find all source nodes")
        path = shortest_from_sources_dijkstra(self.graph, srcs, dst)
        if path is None:
            return Err(CRSError("no path found"))
        return Ok([
            (entry[0], entry[3]) for node in path if (entry := self.graph[node].desc.split(":", maxsplit=3))
        ])