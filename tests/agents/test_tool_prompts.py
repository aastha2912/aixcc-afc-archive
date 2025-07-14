import importlib
import inspect
import pkgutil
import yaml
from collections import defaultdict
from typing import Any, cast

import litellm

from crs.modules.testing import TestProject
from crs.agents import (
    agent, branch_flipper, crsbase, diff_analyzer, dynamic_debug,
    func_summarizer, generate_kaitai, harness_input_decoder,
    produce_patch, pov_producer, source_questions,
    triage, vuln_analyzer
)
from crs.common import types, prompts
from crs.common.aio import Path

async def test_docstring_issues(any_c_project: TestProject, any_java_project: TestProject):
    # enumerate all agents to make sure we don't skip any!
    plausible_agents: set[tuple[str, type[Any]]] = set()
    for mod in pkgutil.iter_modules(path=[Path(agent.__file__).parent.as_posix()]):
        if mod.ispkg:
            continue
        module = importlib.import_module(f"crs.agents.{mod.name}")
        plausible_agents |= set(inspect.getmembers(module, inspect.isclass))


    init_table = defaultdict[type[Any], list[list[Any]]](list)


    for project in [any_c_project, any_java_project]:
        task = await project.task()
        harnesses = (await project.init_harness_info()).unwrap()
        pov_run_data = types.POVRunData(task_uuid=task.task_id, project_name="a", harness="a", sanitizer="a", engine="a", python=None, input=b"a", output="a", dedup="a", stack="a")
        vuln_report = types.VulnReport(task_uuid=task.task_id, project_name="a", function="a", file="a", description="a")
        decoded = pov_run_data.safe_decode()
        vuln = types.AnalyzedVuln(function="", file="", description="", conditions="")

        init_table[source_questions.SourceQuestionsAgent].append([source_questions.CRSSourceQuestions.from_task(task), "foo", "bar"])
        init_table[dynamic_debug.CRSDynamicDebugAgent].append([dynamic_debug.CRSDynamicDebug.from_task(task), 0, None, "foo", "bar", b""])
        init_table[vuln_analyzer.LikelyVulnClassifier].append(["project", "report", "code"])
        init_table[generate_kaitai.GenerateKaitaiAgent].append([generate_kaitai.CRSGenerateKaitai.from_task(task), harnesses[0], "src", "foo", {'a': b'a'}])
        init_table[pov_producer.HarnessInputEncoderAgent].append([pov_producer.CRSPovProducerBufGen.from_task(task), 0, harnesses[0], "src", "foo", "bar"])
        init_table[harness_input_decoder.HarnessInputDecoderAgent].append([harness_input_decoder.CRSHarnessInputDecoder.from_task(task), 0, harnesses[0], "src", "foo", {"foo": b"bar"}])
        init_table[triage.TriageAgent].append([triage.CRSTriage.from_task(task), decoded, None])
        init_table[func_summarizer.FunctionSummarizer].append([crsbase.CRSBase.from_task(task), "foo", "bar"])
        init_table[vuln_analyzer.CRSVulnAnalyzerAgent].append([vuln_analyzer.CRSVuln.from_task(task), vuln_report])
        init_table[diff_analyzer.CRSDiffAgent].append([diff_analyzer.CRSDiff.from_task(task), "foo"])
        init_table[pov_producer.CRSPovProducerAgent].append([pov_producer.CRSPovProducer.from_task(task), vuln, harnesses])
        init_table[produce_patch.PatcherAgent].append([produce_patch.CRSPatcher.from_task(task), vuln, "bar",[decoded], Path("/")])
        init_table[triage.DedupClassifier].append(["foo", vuln,[vuln]])
        init_table[branch_flipper.BranchFlipperAgent].append([branch_flipper.CRSBranchFlipper.from_task(task), 0, harnesses[0], decoded, "foo", "foo", "foo", "foo"])
        init_table[branch_flipper.LikelyFlippableClassifier].append(["foo", "C", "foo", "foo", "foo"])

    expected_yaml = yaml.safe_load( (prompts.prompts_path / "default.yaml").read_text())

    for name, obj in plausible_agents:
        if issubclass(obj, agent.AgentGeneric):
            obj = cast(type[agent.AgentGeneric[Any]], obj)
            if len(getattr(obj, "__abstractmethods__")) > 0 or name in ("Agent", "MsgHistoryAgent"):
                continue
            assert obj in init_table, f"missing init code for {name} test_tool_prompts. Add it so we can verify tool prompts!"
            for args in init_table[obj]:
                m = obj(*args)
                tools_api = {f["function"]["name"]: f["function"] for f in m._tools_api} if m._tools_api else {}
                for k, v in m.tools.items():
                    func_dict = tools_api[k]

                    desc = func_dict['description']
                    assert desc.strip(), f"{name}:{k} missing summary"

                    llm_params = func_dict['parameters']['properties']
                    true_params = inspect.signature(v).parameters
                    assert len(true_params) == len(llm_params), f"{name}:{k} param length seems wrong {true_params} vs {llm_params}"

                    for param, details in llm_params.items():
                        desc = details['description']
                        assert desc.strip(), f"{name}:{k} {param=} missing description"

                        # tools is either a top level tool or a per-agent tool
                        if (yaml_tool := expected_yaml['agents'][name].get('tools', {}).get(k)) is None:
                            yaml_tool = expected_yaml['tools'][k]
                        if 'params' in yaml_tool:
                            assert desc == yaml_tool['params'][param].replace("!!!tab!!!", "    ")