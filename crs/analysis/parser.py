import re

from .data import Report, MultiReport, MultiVuln

from crs_rust import logger

_bool_lut = {
    "yes": True,
    "no": False,
    "true": True,
    "false": False,
    "True": True,
    "False": False,
}

def parse_body(body: str) -> Report:
    m = re.search(r"```yaml(.*?)```", body, re.DOTALL | re.MULTILINE)
    if m is None:
        raise ValueError("no YAML block found")
    body = m.group(1).strip()

    ranges: list[tuple[str, int, int]] = []
    last = None
    last_name = None
    for m in re.finditer(r"^([^:\s]+):", body, re.MULTILINE):
        if last is not None and last_name is not None:
            ranges.append((last_name, last, m.start()))
        last = m.end()
        last_name = m.group(1)
    if last is not None and last_name is not None:
        ranges.append((last_name, last, len(body)))

    report = Report()
    lut = {
        "sinks": report.sinks,
        "vulns": report.vulns,
        "invariants": report.invariants,
    }

    for name, a, b in ranges:
        chunk = body[a:b].split("\n")
        if name == "summary":
            report.summary = body[a:b].strip()
            continue

        # group by lines starting with -
        group: list[list[str]] = []
        current: list[str] = []
        for line in chunk:
            if not line.strip():
                continue
            if line.lstrip().startswith("-"):
                line = line.split("-", 1)[1].strip()
                if current and current[0]:
                    group.append(current)
                current = [line]
            else:
                current.append(line)
        if current and current[0]:
            group.append(current)

        if name == "actions":
            report.actions = ["\n".join(lines) for lines in group]

        # parse pseudo list of dict
        elif name in lut:
            dst = lut[name]
            for lines in group:
                obj: dict[str, str] = {}
                for line in lines:
                    if ":" not in line:
                        continue
                    k, v = line.split(":", 1)
                    obj[k.strip()] = v.strip()
                if obj and any(obj.values()):
                    dst.append(obj)
                else:
                    ... # print("missing", name, group)

        else:
            ... # invalid top-level yaml key

    return report

def parse_block(chunk: list[str], prefix: str = "") -> list[list[str]]:
    cut = 0
    for line in chunk:
        sline = line.lstrip()
        if not sline:
            continue
        if sline.startswith(prefix):
            indent = " " * (len(line) - len(sline))
            sline = sline.removeprefix(prefix).lstrip()
            cut = len(line) - len(sline)
            break
    else:
        return [chunk]

    group: list[list[str]] = []
    current: list[str] = []
    for line in chunk:
        if not line.strip():
            continue
        cline = line[cut:]
        if line.startswith(indent):
            if cline.startswith(" ") or prefix and not line.startswith(indent + prefix):
                current.append(cline)
            else:
                if current and current[0]:
                    group.append(current)
                current = [cline]
        else:
            current.append(line)
    if current and current[0]:
        group.append(current)
    return group

def parse_map(groups: list[list[str]]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    if not groups:
        return {}
    for group in groups:
        if ":" not in group[0]:
            continue
        key, tail = group[0].split(":", 1)
        if tail.strip():
            group = [tail.lstrip()] + group[1:]
        else:
            group = group[1:]
        result[key] = group
    return result

def parse_map2(items: list[str]) -> dict[str, str]:
    obj: dict[str, list[str]] = {}
    last_key: str | None = None
    for line in items:
        if line.startswith(" ") and last_key:
            obj[last_key].append(line)
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        if v.lstrip().startswith(("|", ">")):
            v = ""
        k = k.strip()
        if k == "sanitizer":
            k = "name"
        v = v.strip()
        obj[k] = [v]
        last_key = k
    return {k: "\n".join(v) for k, v in obj.items()}

def parse_body_multifunc(body: str) -> MultiReport:
    m = re.search(r"```yaml(.*?)```", body, re.DOTALL | re.MULTILINE)
    if m is None:
        raise ValueError("no YAML block found")
    body = m.group(1)
    lines = body.strip().split("\n")
    toplevel = parse_block(lines)
    report = MultiReport()

    for name, group in parse_map(toplevel).items():
        try:
            if name == "summary":
                report.summary = "\n".join(group)

            elif name == "sinks":
                for items in parse_block(group, prefix="-"):
                    try:
                        report.sinks.append(parse_map2(items))
                    except ValueError as e:
                        logger.exception("sinks exc", exc=e)

            elif name == "vulns":
                vuln = MultiVuln()
                for items in parse_block(group, prefix="-"):
                    try:
                        block = parse_map(parse_block(items))
                        for k, v in block.items():
                            if k in ("sanitizer", "name", "category"):
                                vuln.name = "\n".join(v)
                            elif k == "found":
                                v = "\n".join(v)
                                vuln.found = _bool_lut.get(v, False)
                            elif k == "functions":
                                func_block = parse_block(v, prefix="-")
                                new_funcs = [parse_map2(item) for item in func_block]
                                vuln.functions += [f for f in new_funcs if f]
                    except ValueError as e:
                        logger.exception("vulns exc", exc=e)
                report.vulns.append(vuln)

            else:
                ...
        except ValueError as e:
            logger.exception("top level exc", exc=e)

    return report

if __name__ == "__main__":
    import json
    import pprint
    import sys

    def iter_lines():
        with open(sys.argv[1]) as f:
            for line in f:
                j = json.loads(line)
                yield j

    for j in iter_lines():
        content = j["messages"][-1]["content"]
        y = parse_body_multifunc(content)
        pprint.pprint(y)
