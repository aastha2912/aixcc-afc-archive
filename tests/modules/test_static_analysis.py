import asyncio
from collections import defaultdict
import json
from pathlib import Path
from typing import TypedDict, Literal
import pytest

from crs.modules.testing import TestProject
from crs.modules.static_analysis import StaticAnalyzer, InferBugReport

TEST_DIR = Path(__file__).parent
INFER_RESULTS_DIR = TEST_DIR / 'data' / 'infer_results'

VulnType = Literal["Buffer Overrun", "Integer Overflow", "Use After Free", "Null Dereference"]
Vuln = TypedDict("Vuln", {
    "file": str,
    "procedure": str,
    "line": int,
    "type": VulnType
})

KNOWN_VULNS: defaultdict[str, list[Vuln]] = defaultdict(list, {
    'nginx-asc': [
        {
            "file": "src/http/ngx_http_core_module.c",
            "procedure": "ngx_http_set_browser_cookie",
            "line": 5289,
            "type": "Buffer Overrun",
        },
        {
            "file": "src/http/ngx_http_request.c",
            "procedure": "ngx_http_trace_handler",
            "line": 4214,
            "type": "Buffer Overrun",
        },
        {
            "file": "src/mail/ngx_mail_pop3_handler.c",
            "procedure": "ngx_mail_pop3_user",
            "line": 337,
            "type": "Buffer Overrun",
        },
        {
            "file": "src/http/modules/ngx_http_userid_filter_module.c",
            "procedure": "ngx_http_userid_get_uid",
            "line": 361,
            "type": "Buffer Overrun",
        },
        {
            "file": "src/http/ngx_http_core_module.c",
            "procedure": "ngx_http_auth_basic_user",
            "line": 1994,
            "type": "Buffer Overrun",
        },
    ],
    'example-libpng-theori': [
        {
            "file": "pngset.c",
            "procedure": "png_set_text_2",
            "line": 952,
            "type": "Buffer Overrun",
        },
    ],
    'curl-theori': [],
    'zstd-theori': [
        {
            "file": "lib/decompress/zstd_decompress_block.c",
            "procedure": "ZSTD_decompressBlock_internal",
            "line": 2000,
            "type": "Use After Free",
        },
        {
            "file": "lib/compress/zstd_compress.c",
            "procedure": "ZSTD_compressContinue_internal",
            "line": 4148,
            "type": "Use After Free"
        }
    ],
    'afc-libxml2': [],
})

# TODO: can we make infer detect these vulns?
UNSUPPORTED_VULNS: defaultdict[str, list[Vuln]] = defaultdict(list, {
    'ngninx-asc': [
        {
            "file": "src/http/ngx_http_variables.c",
            "procedure": "ngx_http_get_host_specs",
            "line": 2870,
            "type": "Use After Free",
        },
        {
            "file": "src/http/ngx_http_request.c",
            "procedure": "ngx_http_validate_from",
            "line": 4093,
            "type": "Buffer Overrun"
        },
        {
            "file": "src/core/ngx_cycle.c",
            "procedure": "ngx_black_list_remove",
            "line": 1668,
            "type": "Null Dereference"
        },
        {
            "file": "src/mail/ngx_mail_pop3_handler.c",
            "procedure": "ngx_mail_pop3_pass",
            "line": 377,
            "type": "Null Dereference"
        },
        {
            "file": "src/mail/ngx_mail_smtp_handler.c",
            "procedure": "ngx_mail_smtp_auth_state",
            "line": 556,
            "type": "Use After Free"
        },
        {
            "file": "src/http/ngx_http_header_filter_module.c",
            "procedure": "ngx_http_header_filter",
            "line": 524,
            "type": "Use After Free"
        },
        {
            "file": "src/http/modules/ngx_http_rewrite_module.c",
            "procedure": "ngx_http_rewrite_handler",
            "line": 178,
            "type": "Buffer Overrun"
        },
        {
            "file": "src/http/ngx_http_variables.c",
            "procedure": "ngx_http_get_last_ip_variable",
            "line": 2851,
            "type": "Null Dereference"
        },
        {
            "file": "src/os/unix/ngx_linux_sendfile_chain.c",
            "procedure": "ngx_sendfile_r",
            "line": 80,
            "type": "Buffer Overrun"
        }
    ],
    'example-libpng-theori': [
        {
            "file": "pngrutil.c",
            "procedure": "png_handle_iCCP",
            "line": 1447,
            "type": "Buffer Overrun",
        },
        {
            "file": "pngrutil.c",
            "procedure": "png_handle_eXIf",
            "line": 0, # TODO: what line can we expect it to flag?
            "type": "Use After Free",
        },
    ],
    'curl-theori': [
        {
            "file": "lib/setopt.c",
            "procedure": "setopt_int",
            "line": 629,
            "type": "Integer Overflow",
        },
        {
            "file": "lib/urlapi.c",
            "procedure": "parseurl",
            "line": 1069,
            "type": "Use After Free",
        }
    ],
    'zstd-theori': [
        {
            "file": "lib/compress/zstd_compress.c",
            "procedure": "ZSTD_compressSequences_internal",
            "line": 6165,
            "type": "Buffer Overrun"
        },
    ],
    'afc-libxml2': [
        {
            "file": "HTMLparser.c",
            "procedure": "htmlSecureComment",
            "line": 3591,
            "type": "Buffer Overrun"
        }
    ]
})

INFER_REPORT_MINS = {
    'example-libpng-theori': 900,
}

KNOWN_INFER_ANALYZE_FAILURES = {'zstd-theori', 'example-libpng-theori'}

def vuln_matches(v: Vuln, report: InferBugReport):
    return (
        v["file"] == report.file and
        v["procedure"] == report.procedure and
        v["line"] == report.line and
        v["type"] in report.bug_type_hum
    )

def format_vuln(v: Vuln):
    return f"{v['file']}:{v['procedure']}:{v['line']}:{v['type']}"

def eval_score_tuples(scores: list[float], report: list[InferBugReport], known_vuln: list[Vuln]):
    worst = 1.0
    for v in known_vuln:
        scored = [x for x, y in zip(scores, report) if vuln_matches(v, y)]
        worst = min(worst, max(scored))

    invalid_scores = [
        x for x, y in zip(scores, report)
        if x > worst and not any(vuln_matches(v, y) for v in known_vuln)
    ]
    return (len(invalid_scores) / len(scores))

async def test_infer_analyze(infer_project: TestProject):
    # manually clear caches
    cache_path = await infer_project.searcher.gtags.clang_searcher._clang_def_cache_file()
    await cache_path.unlink(missing_ok = True)
    await (await infer_project.get_bear_tar()).unlink(missing_ok=True)
    infer_project.builds = defaultdict(dict)

    analyzer = StaticAnalyzer(await infer_project.task())
    res = (await analyzer.run_infer()).unwrap()
    assert len(res) > INFER_REPORT_MINS.get(infer_project.name, 100)

@pytest.mark.slow
async def test_infer_tool(built_project: TestProject):
    if built_project.info.language == "jvm":
        pytest.skip("infer java support not yet implemented")

    known_vuln = KNOWN_VULNS[built_project.name]
    unsupported = UNSUPPORTED_VULNS[built_project.name]
    analyzer = StaticAnalyzer(await built_project.task())
    report = (await analyzer.run_infer()).unwrap()

    found_known = [v for v in known_vuln if any(vuln_matches(v, r) for r in report)]
    missed_known = [v for v in known_vuln if v not in found_known]
    assert len(missed_known) == 0, f"missing vulns: {[format_vuln(v) for v in missed_known]}"

    found_new = [v for v in unsupported if any(vuln_matches(v, r) for r in report)]
    assert len(found_new) == 0, f"found new vulns, update test: {[format_vuln(v) for v in found_new]}"

@pytest.mark.slow
async def test_infer_eval(best_models: None, built_project: TestProject):
    if built_project.info.language == "jvm":
        pytest.skip("infer java support not yet implemented")

    if built_project.name in KNOWN_INFER_ANALYZE_FAILURES:
        pytest.skip("this project is known to fail")

    known_vuln = KNOWN_VULNS[built_project.name]
    if len(known_vuln) == 0:
        pytest.skip("no expected infer vulns")

    report_json = json.load(open(INFER_RESULTS_DIR / f"{built_project.name}.json"))
    analyzer = StaticAnalyzer(await built_project.task())
    func_reports = [InferBugReport(**fields) for fields in report_json]
    summaries = (await analyzer.get_func_summaries(func_reports)).unwrap()
    scores = await asyncio.gather(*[analyzer.analyze_func(r, summaries) for r in func_reports])
    selectivity = eval_score_tuples(scores, func_reports, known_vuln)
    assert selectivity < 0.05
