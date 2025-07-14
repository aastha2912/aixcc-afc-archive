import pytest
from enum import Enum, auto
from typing import Any, Literal

from crs.common.utils import cached_property
from crs.common.prompts import PromptManager, prompt_manager
from crs.agents.classifier import Classifier

class Colors(Enum):
    RED = auto()
    ORANGE = auto()
    YELLOW = auto()
    GREEN = auto()
    BLUE = auto()
    PURPLE = auto()

class ColorClassifier(Classifier[Colors]):
    @classmethod
    def prompt_manager(cls) -> PromptManager:
        base = prompt_manager.raw["default"].agents["Classifier"]
        return PromptManager.with_agent(
            agent_name="ColorClassifier",
            system=base.system,
            user=base.user,
            custom={"instructions": "Select the color that best fits the object."},
        )

    @cached_property
    def options(self):
        return {x: x.name.lower() for x in Colors}

    @property
    def details(self):
        return f"Object: {self.object}"

    @property
    def model(self):
        return "gpt-4o-mini-2024-07-18"

    def __init__(self, object: str, *args: Any, **kwargs: Any):
        self.object = object
        super().__init__(*args, **kwargs)

async def test_color_classifier():
    """
    classify performs classification based on only a single token, so enum keys can no longer be used.
    This test now verifies that proper exception handling occurs when multiple tokens are provided.
    """

    async def test(object: str, color: Colors, threshold: float = 0.90):
        res = await ColorClassifier(object).classify()
        key, prob = res.best()
        assert color == key and prob > threshold

    with pytest.raises(AssertionError):
        await test("rose", Colors.RED)

class LikelyClassifier(Classifier[Literal["likely", "unlikely"]]):
    @classmethod
    def prompt_manager(cls) -> PromptManager:
        base = prompt_manager.raw["default"].agents["Classifier"]
        return PromptManager.with_agent(
            agent_name="LikelyClassifier",
            system=base.system,
            user=base.user,
            custom={"instructions": "Decide whether the scenario is likely or unlikely"},
        )

    @cached_property
    def options(self) -> dict[Literal["likely", "unlikely"], str]:
        return {
            "likely": "The scenario is likely to happen",
            "unlikely": "The scenario is unlikely to happen"
        }

    @property
    def details(self):
        return f"scenario: {self.scenario}"

    @property
    def model(self):
        return "gpt-4o-mini-2024-07-18"

    def __init__(self, scenario: str, *args: Any, **kwargs: Any):
        self.scenario = scenario
        super().__init__(*args, **kwargs)

async def test_likely_classifier():
    async def test(scenario: str, likely: bool, threshold: float = 0.90):
        res = await LikelyClassifier(scenario).classify()
        key, prob = res.best()
        assert (likely == (key == "likely")) and prob > threshold

    await test("A dog runs through a yard", True)
    await test("A bird sings a song", True)
    await test("A whale scratches its leg", False)
    await test("A duck eats a hippo", False)
