import asyncio
import pytest
from typing import TypedDict
from crs.modules.testing import TestProject
from crs.agents.dynamic_debug import CRSDynamicDebug

DebugTestcase = TypedDict('DebugTestcase', {
    "harness_num": int,
    "pov_python": str,
    "question": str,
    "additional_info": str,
    "expected": str
})

testcases: dict[str, list[DebugTestcase]] = {
    "nginx-asc": [
        {
            "harness_num": 0,
            "pov_python": r"""with open('input.bin', 'wb') as f: f.write(b'GET /\r\n\r\n')""",
            "question": "Why does my input not trigger http processing?",
            "additional_info": "",
            "expected": "proto"
        },
        {
            "harness_num": 0,
            "pov_python": r"""with open('input.bin', 'wb') as f: f.write(b'request: "GET /\\r\\n\\r\\n"\nreply: ""\n')""",
            "question": "What is the value of `file` in `ngx_file_info`?",
            "additional_info": "",
            "expected": "/out/html/index.html"
        },
        {
            "harness_num": 0,
            "pov_python": r"""with open('input.bin', 'wb') as f: f.write(b'request: "GET /protected HTTP/1.1\\nHost: url.com\\nAuthorization: Basic QUFBQUFBQUFBQUFBQUF\\n\\n"\nreply: ""\n')""",
            "question": "What are the credentials after base64 decoding in ngx_http_auth_basic_user?",
            "additional_info": "",
            "expected": "AAA"
        }
    ],
    "tomcat-theori": [
        {
            "harness_num": 6,
            "pov_python": r"with open('input.bin', 'wb') as f: f.write(b'admin\\\x00mypasswordguess')",
            "question": "What is the value of `hashBytes` in `checkCredentials`?",
            "additional_info": "",
            "expected": "15, 105, -55",
        }
    ],
    "example-libpng-theori": [
        {
            "harness_num": 0,
            "pov_python": r"with open('input.bin', 'wb') as f: f.write(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd2iCCPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00x\x9c\x03\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\tIDATx\x9cc\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00IEND\x00\x00\x00\x00')",
            "question": "What is the value of `keyword_length` after the loop finishes in `png_handle_iCCP`?",
            "additional_info": "I'm trying to trigger the buffer overflow in the loop and want to understand why it's failing",
            "expected": "21",
        }
    ],
    "curl-theori": [
        {
            "harness_num": 16,
            "pov_python": r"with open('input.bin', 'wb') as f: f.write(b'file:///__backdoor')",
            "question": "Why does this not trigger the backdoor in `parseurl`?",
            "additional_info": "",
            "expected": "slash", # should tell us about the extra slash
        }
    ],
    "zstd-theori": [
        {
            "harness_num": 0,
            "pov_python": r"with open('input.bin', 'wb') as f: f.write(b'QQQABCD1234')",
            "question": "What are the bytes at `ip` in ZSTD_decompressBlock_internal ?",
            "additional_info": "I'm trying to trigger the free call that is reached based on the contents of `ip`.",
            "expected": "QQQABC",
        }
    ],
    "afc-zookeeper": [
        {
            "harness_num": 1,
            "pov_python": r"with open('input.bin', 'wb') as f: f.write(b'127.0.0.1\x00\x00\x00\xe8\x03\x00\x00\x00\x00\x00\x00')",
            "question": "What is the value of `serverAddr` in `verifyIPv6`? Does it call `countExtraColons`?",
            "additional_info": "",
            "expected": "IPv4", # should tell us that we're using IPv4
        }
    ],
    "afc-libxml2": [
        {
            "harness_num": 1,
            "pov_python": r"with open('input.bin', 'wb') as f: f.write(b'<!--AAAAAAAAAAAAAAAAAAAAAAAA-->')",
            "question": "Why does this not reach the html comment parsing, such as htmlSecureComment?",
            "additional_info": "I'm trying to trigger a buffer overflow in htmlSecureComment",
            "expected": "harness", # should mention that the harness format is incorrect, it reads 8 bytes of data before HTML
        },
        {
            "harness_num": 1,
            "pov_python": r"with open('input.bin', 'wb') as f: f.write(b'\x00\x00\x08\x00\x00\x00\x00\x00<!--AAAAAAAAAAAAAAAAAAA&#1234AAAAAAAAAAA')",
            "question": "Why does this not trigger the buffer overflow in htmlSecureComment?",
            "additional_info": "The special character handling should be able to write out of bounds.",
            "expected": "refs", # refs processing is disabled
        }
    ],
}

@pytest.mark.slow
async def test_cheap_debug_agent(built_project: TestProject):
    task = (await built_project.tasks()).unwrap()[-1]
    crs = CRSDynamicDebug.from_task(task)
    if (tests := testcases.get(built_project.name)) is None: return
    # don't require a result when using a dumb model
    _ = await asyncio.gather(*[
        crs.debug_pov(test['harness_num'], test['pov_python'], test['question'], test['additional_info'])
        for test in tests
    ])

@pytest.mark.slow
async def test_best_debug_agent(built_project: TestProject, best_models: None):
    task = (await built_project.tasks()).unwrap()[-1]
    crs = CRSDynamicDebug.from_task(task)
    if (tests := testcases.get(built_project.name)) is None: return
    # require a result when using a smart model
    results = await asyncio.gather(*[
        crs.debug_pov(test['harness_num'], test['pov_python'], test['question'], test['additional_info'])
        for test in tests
    ])
    for test, res in zip(tests, results):
        assert test["expected"] in res.unwrap().answer, "debug output did not contain expected string"