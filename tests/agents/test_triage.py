import pytest
from typing import TypedDict, Literal
from crs.agents.triage import DedupClassifier

ALL_VULNS = {
    "nginx-asc": {
        0: "subtle bug in new error handling: missing return statement in ngx_http_script_regex_end_code leads to a global bof later",
        11: "buffer overflow in basic auth header handling",
        21: "buffer overflow in userid cookie handling",
        34: "Use-After-Free in ngx_black_list_remove: The function continues to use reader after potentially freeing it through ngx_destroy_black_list_link when removing the first element.",
        44: "NULL pointer dereference in ngx_http_get_last_ip_variable",
        74: "A heap buffer overflow vulnerability exists in ngx_sendfile_r() in ngx_linux_sendfile_chain.c",
        88: "buffer overflow in pop3 login",
        101: "Use-after-free caused by closing the connection in the error handling of `ngx_mail_smtp_noop`",
        111: "Double-free vulnerability in ngx_http_process_prefer() when processing duplicate Prefer headers",
        122: "use-after-free in host_specs endpoint. host_specs is freed if `ccf->remote_admin` but still used later",
        152: "Buffer overflow vulnerability in ngx_http_trace_handler() in ngx_http_request.c",
        164: "Buffer underflow `ngx_http_validate_from` when processing From header with input containing consecutive dots",
        171: "Heap corruption in auth_log logic in `ngx_mail_pop3_pass`",
        183: "buffer overflow in cookie handling when user agent is safari",
    },
    "tomcat-theori": {
        38: "path traversal due to URL decoding after request path normalization",
        39: "authentication backdoor based on a password hash prefix",
        40: "command injection in If-Match HTTP header",
    },
    "curl-theori": {
        48: "use-after-free in parseurl, url is freed if `ptr` startswith `__backdoor` but still used later",
        49: "integer overflow in setopt_int, when setting an undefined HTTP version."
    },
    "example-libpng-theori": {
        37: "buffer overflow due to wide character support",
        38: "buffer overflow due to key conversion after allocation",
        39: "use after free due to not allocating a new `exif` buffer",
    },
    "zstd-theori": {
        47: "use after free bugdoor in ZSTD_decompressBlock_internal",
        48: "heap write overflow in sequence compression",
        49: "bugdoor in ZSTD_compressContinue_internal",
    },
    "afc-zookeeper": {
        40: "Infinite loop in ipv6 validation",
    },
    "afc-libxml2": {
        40: "heap overflow when parsing special states in HTML content",
    }
}

DedupTestcase = TypedDict('DedupTestcase', {
    'project_name': str,
    'report': str,
    'result': int | Literal['NEW'],
})

testcases: list[DedupTestcase] = [
    {
        'project_name': 'nginx-asc',
        'report': 'heap-buffer-overflow in ngx_http_auth_basic_user when credentials are too large',
        'result': 1
    },
    {
        'project_name': 'nginx-asc',
        'report': 'use-after-free in ngx_mail_pop3_auth when authenticating with a previously authenticated user',
        'result': 'NEW'
    },
    {
        'project_name': 'zstd-theori',
        'report': 'use-after-free in ZSTD_decompressBlock_internal where ip is conditionally freed but immediately used',
        'result': 0
    },
    {
        'project_name': 'zstd-theori',
        'report': 'out-of-bounds read in ZSTD_decodeLiteralsBlock when block size < 8',
        'result': 'NEW'
    },
    {
        'project_name': 'tomcat-theori',
        'report': 'Command injection in compareEntityTag RFC 14438 suppoort',
        'result': 2
    },
    {
        'project_name': 'tomcat-theori',
        'report': 'SSRF in servlet preprocessor pass',
        'result': 'NEW'
    },
    {
        'project_name': 'example-libpng-theori',
        'report': 'use-after-free due to png_set_eXIf_2 not re-allocating buffer but freeing the original',
        'result': 2
    },
    {
        'project_name': 'example-libpng-theori',
        'report': 'Read of uninitialized value in eXIf parsing',
        'result': 'NEW'
    },
]

@pytest.mark.slow
@pytest.mark.parametrize('testcase', testcases)
async def test_dedup_classifier(gpt_4_1: None, testcase: DedupTestcase):
    candidates = list(ALL_VULNS[testcase["project_name"]].values())
    dc = DedupClassifier(testcase["project_name"], testcase["report"], candidates)
    res = await dc.classify()
    assert res.best()[0] == testcase["result"], "unexpected dedup result"