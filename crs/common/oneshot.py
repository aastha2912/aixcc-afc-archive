"""
Simple oneshot LLM queries for summarization or similar tasks
"""

import math
from crs import config
from crs.common import llm_api
from crs.common.types import Ok, Err, Result, CRSError
from crs.common.utils import require, requireable


@requireable
async def summarize(context: str, text_to_summarize: str, usebig: bool = False) -> Result[str]:
    """
    Attempt to summarize a lot of output into a more concise description.

    Parameters
    ----------
    context : str
        the context in which we are summarizing. For example "We only care about error messages
        or warnings that are printed in this compilation output. Ignore everything else"

    text_to_summarize : str
        the actual text for which we want a summary

    usebig : bool, optional
        if true, use the big model in our config; otherwise the small (defaults to small)

    Returns
    -------
    str
        a text summary
    """
    from crs.agents.agent import running_agent
    prompt = (
        f"Please summarize the provided text concisely. {context} "
        "You may not ask any questions. If something is ambiguous, provide your best guess. "
        f"<text_to_summarize>\n{text_to_summarize}\n<text_to_summarize>"
    )
    msgs = [{"role":"user", "content":prompt}]
    response = require(await llm_api.priority_completion(
        agent.priority if (agent := running_agent.get()) else math.inf,
        tools=None,
        model=config.MODEL.get() if usebig else config.SMALLMODEL.get(),
        messages=msgs,
        temperature=0.4,
    ))
    return Ok(r) if (r := response.choices[0].message.content) else Err(CRSError("no response"))

@requireable
async def summarize_build_failure(output: str):
    summary = ""
    for i in range(0, len(output), 30_000):
        summary += "\n" + require(await summarize(
            (
                "This is output from a build process. We ONLY care about errors "
                "or warnings that might be relevent to developers. We DO NOT care about "
                "anything that would not block compilation. DO NOT elaborate on messages, "
                "the reader is a developer who understands the output. They only want you "
                "to remove extraneous/irrelevant information to speed up their analysis. "
                "If there are relevent line numbers or things to help find the bug, include it."
            ),
            output[i:i+30_000]
        ))
    return Ok(summary)

@requireable
async def summarize_test_failure(output: str):
    summary = ""
    for i in range(0, len(output), 30_000):
        summary += "\n" + require(await summarize(
            (
                "This is output from a test process. We ONLY care about errors "
                "or warnings that might be relevent to developers. DO NOT elaborate on messages, "
                "the reader is a developer who understands the output. They only want you "
                "to remove extraneous/irrelevant information to speed up their analysis. "
                "If there are relevent line numbers or things to help find the bug, include it."
            ),
            output[i:i+30_000]
        ))
    return Ok(summary)