from litellm import Choices, Message, ModelResponse # pyright: ignore [reportPrivateImportUsage]
from pydantic import BaseModel, Field, ValidationError
from typing import Any, Optional

import pytest

from crs.agents.xml_agent import describe_errors, parse_fields, XMLAgent, XMLVerifyClass
from crs.common.prompts import PromptManager
from crs.common.types import Ok, Tool
from crs.common.utils import cached_property, tool_wrap

from crs.agents.diff_analyzer import DiffAnalysis
from crs.agents.pov_producer import HarnessInputEncoderResult

@XMLVerifyClass
class R(BaseModel):
    confidence: float = Field(description="Confidence score from 0-100 of your result")
    result: float = Field(description="The numerical result of the query")
    desc: str = Field(description="A short (1 sentence description)")

async def add(a: int, b: int):
    """
    Adds the arguments and returns the result

    Parameters
    ----------
    a : int
        the first number
    b : int
        the second number
    """
    return Ok(a+b)

class Tester(XMLAgent[R]):
    @classmethod
    def prompt_manager(cls) -> PromptManager:
        return PromptManager.with_agent(
            agent_name="Tester",
            system=(
                "Please answer all mathematical queries given to you to the best of your ability.\n"
                "For impossible queries, just respond with a random answer with 0 confidence"
            ),
            user="What is {{ agent.query }}?",
        )

    @cached_property
    def tools(self) -> dict[str, Tool]:
        return {
            "add": tool_wrap(add)
        }

    @property
    def return_type(self):
        return R

    def mock_response(self, msgs: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
        if self.mock:
            mr = ModelResponse(choices=[
                Choices(finish_reason='stop', message=Message(
                    content="""
                    <confidence>100</confidence>
                    <result>2</result>
                    <desc>The sum of 1 and 1 is 2.</desc>,
                    """
                ))
            ])
            return mr.model_dump()
        return None

    def __init__(self, query: str, mock: bool=False):
        self.mock = mock
        self.query = query
        super().__init__()


async def test_xml():
    g = Tester("what is 1+1?", True)
    res = await g.run()
    assert res.response
    assert res.response.confidence == 100
    assert res.response.result == 2
    assert res.response.desc == "The sum of 1 and 1 is 2."


    g = Tester("what is 2+2?", False)
    res = await g.run()
    assert res.response
    assert res.response.result == 4

    g = Tester("what is the 12 quintillionth digit of pi?", False)
    res = await g.run()
    assert res.response
    assert res.response.confidence < 30


class A(BaseModel):
    x: Optional[str] = None
    b: list[float]
    c: str
    d: list[int]

@XMLVerifyClass
class AA(BaseModel):
    A: Optional[A]

async def test_parse():
    assert parse_fields("<a><b>1</b><c>yo</c></a>", AA) == {'A': {'b': ['1'], 'c': 'yo', 'd': []}}
    assert parse_fields("<a><b>1</b><c>yo</c><d>1</d><d>2</d></a>", AA) == {'A': {'b': ['1'], 'c': 'yo', 'd': ['1', '2']}}

async def test_multi_start_parse_encoder():
    xmls = [
        'Before providing our final encoder function, here is the reasoning behind how the harness processes the input:\n\n1) The harness calls data.consumeLong() first, which – per the stated rules – consumes 8 bytes from the BACK of the buffer as a long.  \n2) Then it calls data.consumeInt(1, 100), which consumes 4 bytes from the BACK of what remains (i.e., the 4 bytes just before the 8 for the long), interpreting them as an int in the range [1..100].  \n3) Finally, data.consumeRemainingAsString() reads whatever bytes are left at the FRONT of the buffer as a string.  \n\nTherefore, the final layout to produce (from left to right in the file) must be:  \n[ sid bytes ] [ trackLimit (4 bytes, little-endian) ] [ timestamp (8 bytes, little-endian) ]  \n\nBelow is the plain XML output with two fields:  \n• <encoder_python> : the Python code that encodes the input correctly  \n• <harness_notes> : details clarifying how the harness processes bytes, including non-obvious details  \n\n-------------------------------------------------------------------------------\n<encoder_python>\nimport struct\n\ndef encode_input(timestamp: int, track_limit: int, sid: str) -> bytes:\n    """\n    Produces bytes for MessageTrackerPeekReceivedFuzzer:\n      1) The last 8 bytes (in the file) will be the little-endian timestamp\n         used by data.consumeLong().\n      2) Just before those 8 bytes, we put 4 bytes (in little-endian) for\n         track_limit, used by data.consumeInt(1, 100).\n      3) All remaining bytes at the front of the buffer are consumed as a\n         string by data.consumeRemainingAsString().\n    """\n    # Encode the string at the front\n    sid_bytes = sid.encode(\'utf-8\')\n\n    # track_limit is read (consumeInt) from the back AFTER the timestamp, so place it\n    # just before the timestamp. Must encode as little-endian so the harness decodes\n    # as intended.\n    track_bytes = track_limit.to_bytes(4, byteorder=\'little\', signed=True)\n\n    # timestamp is read (consumeLong) from the back of the buffer, in little-endian\n    time_bytes = timestamp.to_bytes(8, byteorder=\'little\', signed=True)\n\n    return sid_bytes + track_bytes + time_bytes\n\n# Confirm correctness with a quick debugger check (writing out a sample).\n# This code writes an input that should yield:\n#   timestamp1 == 0x1122334455667788\n#   track_limit == 77\n#   sid == \\"TEST\\".\nif __name__ == \\"__main__\\":\n    test_data = encode_input(0x1122334455667788, 77, \\"TEST\\")\n    with open(\'input.bin\',\'wb\') as f:\n        f.write(test_data)\n</encoder_python>\n\n<harness_notes>\n1) The first consumeLong() call reads the last 8 bytes of the file in little-endian order as a signed 64-bit value.  \n2) The next consumeInt(1, 100) call also reads from the back (right before the last 8 bytes), interpreting those 4 bytes in little-endian, and requiring the integer to be in [1..100].  \n3) All remaining bytes from the front of the file are taken as sid via consumeRemainingAsString(), which does not require explicit null-termination or escape characters.  \n4) The fuzzerTestOneInput method sets some system properties, calls new MessageTracker(...) with the read trackLimit, and logs/peeks messages. These details are straightforward, but the order in which bytes are consumed (long → int → string) from different ends of the buffer can be surprising.  \n</harness_notes>',
        'I see from the debugger output that we are indeed hitting the breakpoints in the harness and printing out some variable values. That confirms that our input is definitely being parsed by the harness.\n\nBelow is the final XML output. The <encoder_python> contains a function you can call to generate inputs for this harness, and <harness_notes> includes detailed commentary on the parsing behavior that might not be obvious from a quick glance.\n\n<encoder_python>\ndef encode_input(parser_options: int, failure_position: int, entities: list[tuple[str, str]]) -> bytes:\n    """\n    Encode input for libxml2/fuzz/xml.c harness.\n\n    Format (big-endian):\n    1) 4 bytes: parser_options\n    2) 4 bytes: failure_position\n    3) For each entity (url, content):\n         url + null terminator\n         content + null terminator\n       to define an entity (the harness keeps reading as long as url is non-empty).\n    A special empty-url sentinel stops further entity reads.\n    Lastly, we append one more empty-url sentinel so that the user does not forget to close the list.\n    """\n    out = parser_options.to_bytes(4, \'big\')\n    out += failure_position.to_bytes(4, \'big\')\n\n    for (url, content) in entities:\n        if url:\n            out += url.encode(\'utf-8\') + b\'\\x00\'\n            out += content.encode(\'utf-8\') + b\'\\x00\'\n        else:\n            # If url is empty, harness will stop reading entities\n            out += b\'\\x00\'\n    # Append a sentinel entity at the end to be safe\n    out += b\'\\x00\'\n\n    return out\n</encoder_python>\n\n<harness_notes>\n1) The harness reads 8 bytes at the start of the file for parser_options (line 40 of xml.c) and failure_position (line 47). Both are read big-endian, using xmlFuzzReadInt(4).\n2) The harness subsequently calls xmlFuzzReadEntities(), which parses an indefinite sequence of (url,content) pairs. Each string is read until it encounters a \'\\x00\' as the terminator. The process stops when an empty url is read (i.e., a single null terminator), at which point no content is read and entity reading is done.\n3) The harness forcibly disables certain parser options like XML_PARSE_XINCLUDE, XML_PARSE_DTDVALID, and XML_PARSE_SAX1 even if you pass them in parser_options, so those bits get zeroed out.\n4) After reading the entities, the harness calls xmlFuzzMainEntity() and xmlFuzzMainUrl() to retrieve the “main” buffer and URL for actual XML parsing. If you need the harness to parse real XML, ensure at least one non-empty entity.\n5) failure_position is taken modulo (size + 100), per line 47, so its effective value in the code is the remainder of the original integer you provide.\n</harness_notes>',
        'Below is my reasoning, followed by the final XML output.\n\n-------------------------------------------------------------------------------\nExplanation and Reasoning\n-------------------------------------------------------------------------------\n• The harness code for “CompressorSnappyFuzzer” is quite direct: it calls fuzzerTestOneInput(byte[] data) and then tries two constructors involving Snappy:\n  1. FramedSnappyCompressorInputStream(new ByteArrayInputStream(data))\n  2. SnappyCompressorInputStream(new ByteArrayInputStream(data))\n\n• There are no hidden offsets or lengths: the full input array is fed into each constructor. The harness does not add or remove any extraneous bytes before invoking the project code.\n\n• The harness does not do any splitting or pass only part of the input onward. It simply attempts to parse the provided data as a snappy-framed stream, and then as a raw snappy stream.\n\n• Because no non-obvious or special harness manipulations exist here (for instance, no custom flags, no chunk offsets, etc.), the only relevant detail is that the entire buffer (data[]) is used by both constructors. If an IOException happens while reading, the harness silently ignores it, but the input is still consumed in its entirety.\n\n• Therefore, the bytes you provide are accepted in full, unmodified, by the harness. If you want to produce a “canonical” snappy-framed input, you might include a Stream Identifier chunk (type=0xFF) and then one or more uncompressed or compressed chunks, each with its masked CRC32C. However, the harness is equally happy receiving any random blob in “data” since it will just attempt to parse it.\n\n• In the code below, encode_input produces a minimal valid framed Snappy input, with:\n  – A 0xFF chunk for the stream identifier (“sNaPpY”).  \n  – A 0x01 chunk (uncompressed) with the data “Test” plus the masked CRC32C for that data.\n\n• We have confirmed via the debugger (jdb) that the “data” variable in fuzzerTestOneInput holds exactly the bytes we wrote to input.bin. No offsets or extra bytes are added.\n\n-------------------------------------------------------------------------------\n<encoder_python> Explanation\n-------------------------------------------------------------------------------\nThe encode_input function below:\n1) Computes the masked CRC32C per the snappy-framing spec.\n2) Writes a short framed Snappy block to “input.bin”:\n   • Chunk type=0xFF, 3-byte length=6, then “sNaPpY”  \n   • Chunk type=0x01 (uncompressed), 3-byte length=8, then 4 masked CRC bytes + “Test”  \nYou can add or remove additional chunks as you see fit, but this is enough to verify the harness’s behavior.\n\n-------------------------------------------------------------------------------\n<harness_notes> Explanation\n-------------------------------------------------------------------------------\n• There is no hidden or unusual harness behavior: the entire input is simply given to the snappy constructors.  \n• No special flags or extra bytes are inserted by the harness.  \n• The harness calls fuzzCompressorInputStream—any exceptions are ignored, but that does not affect how the input is consumed.  \n• The harness will attempt to parse the exact same data as both framed snappy and plain snappy.  \n• This is all that must be known to produce valid or interesting test inputs.\n\n-------------------------------------------------------------------------------\nFINAL ANSWER\n-------------------------------------------------------------------------------\n<encoder_python>\ndef encode_input() -> None:\n    """\n    Produces a short valid \\"framed snappy\\" input file named \'input.bin\' with:\n      - Stream identifier chunk: type=0xFF, length=6, data=b\'sNaPpY\'\n      - Uncompressed chunk: type=0x01, length=8, 4-byte masked CRC followed by b\'Test\'\n    """\n    import binascii\n    import struct\n\n    data = b\'Test\'\n    # Compute standard CRC32 (for b\'Test\') and mask it per snappy, i.e. rotate right by 15 bits, then add 0xa282ead8\n    crc = binascii.crc32(data) & 0xffffffff\n    left_rot_15 = ((crc << 15) & 0xffffffff) | (crc >> 17)\n    masked_crc = (left_rot_15 + 0xa282ead8) & 0xffffffff\n\n    # Stream identifier chunk: 0xFF + 3-byte length=6 + b\'sNaPpY\'\n    stream_ident_chunk = b\'\\xFF\\x06\\x00\\x00\' + b\'sNaPpY\'\n\n    # Uncompressed chunk: 0x01 + 3-byte length=8 + 4-byte masked CRC + \'Test\'\n    # The length (8) includes the 4 CRC bytes plus the 4 uncompressed data bytes\n    uncompressed_chunk = b\'\\x01\\x08\\x00\\x00\' + struct.pack(\'<I\', masked_crc) + data\n\n    result = stream_ident_chunk + uncompressed_chunk\n\n    # Write the result to input.bin\n    with open(\'input.bin\', \'wb\') as f:\n        f.write(result)\n</encoder_python>\n<harness_notes>\nThe entire byte[] data is fed directly into both FramedSnappyCompressorInputStream and SnappyCompressorInputStream with no offsets or additional headers. The harness does not insert special fields or flags, nor does it split or discard portions of the input. Any IOException is ignored, but that does not alter how data is passed to the target code. Therefore, all bytes delivered by encode_input are read sequentially by the library as a snappy (framed or raw) input stream.\n</harness_notes>',
    ]
    for x in xmls:
        parsed = parse_fields(x, HarnessInputEncoderResult)
        assert parsed['encoder_python'].startswith("def encode") or parsed['encoder_python'].startswith("import ")
        assert parsed['harness_notes']

bad_xml = """
<change_desc>Introduced a length check for rewritten URIs in ngx_http_script_regex_end_code function to enforce a maximum length of 2000 bytes.</change_desc>
<vuln>
    <description>Potential buffer overflow due to lack of proper handling of e->buf.data when e->buf.len exceeds 2000 bytes in src/nginx/src/http/ngx_http_script.c.</description>
    <function>ngx_http_script_regex_end_code</function>
    <harness>src/harnesses/mail_request_harness.cc</harness>
    <conditions>Send a request that results in a rewritten URI longer than 2000 bytes.</conditions>
    <sanitizers>AddressSanitizer: heap-buffer-overflow</sanitizers>
    <justification>This is likely vulnerable as while there's a check for length, if the buffer allocation doesn't account for proper size limits, it could lead to overflow.</justification>
</vuln>
"""

expected_err_prefix = 'The output you provided failed to validate: \nField required: vuln.0.file\nNOTE:'

async def test_error_parsing():
    err = None
    try:
        _ = DiffAnalysis.model_validate(parse_fields(bad_xml, DiffAnalysis))
    except ValidationError as e:
        err = e

    assert err is not None
    assert describe_errors(err, DiffAnalysis).startswith(expected_err_prefix), "wrong error description for invalid xml"

    # only 1 level of nesting allowed
    with pytest.raises(AssertionError):
        class P(BaseModel):
            test: float = Field(description="test")
        class Q(BaseModel):
            p: P = Field(description="nested")
        @XMLVerifyClass
        class R(BaseModel):
            q: Q = Field(description="nested")
        _ = R(q=Q(p=P(test=1)))

    # definitely no recursion
    with pytest.raises(AssertionError):
        @XMLVerifyClass
        class X(BaseModel):
            q: Optional['X'] = Field(description="nested")
        _ = X(q=None)

    # nested models should be fully checked
    with pytest.raises(AssertionError):
        class B(BaseModel):
            l: Optional[list[int]]
        @XMLVerifyClass
        class BB(BaseModel):
            b: Optional[B]
        _ = BB(b=B(l=None))
