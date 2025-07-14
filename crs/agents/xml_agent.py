from abc import abstractmethod
from pydantic import BaseModel, ValidationError
from typing import cast, Any, Optional, Union, get_origin, get_args

from crs.agents.agent import AgentGeneric
from crs.common.types import Message

XML_CHECKED_ATTRIBUTE = "_xml_ready"

def tag_start_end(content: str, tag: str, skip:int = 0) -> Optional[tuple[int, int]]:
    if (idx := content.find(f"<{tag}>".lower(), skip)) >= 0:
        # properly closed
        end_idx1 = content.find(f"</{tag}>".lower(), idx+1)
        # close enough to closed
        end_idx2 = content.find(f"<{tag}>".lower(), idx+1)
        # no close tag
        if end_idx1 == -1 and end_idx2 == -1:
            return None
        # get the one that leads to the shortest string and isn't -1
        end_idx = end_idx1 if end_idx2 == -1 else (end_idx2 if end_idx1 == -1 else min(end_idx1, end_idx2))
        return idx + len(f"<{tag}>"), end_idx
    else:
        return None

def tag_start_end_clean(content: str, tag: str, skip:int = 0) -> Optional[tuple[int, int]]:
    # search for "clean" tags: with the tags the only content on their lines
    lines = content[skip:].splitlines(keepends=True)
    # start tag
    starts = [(i, x) for i, x in enumerate(lines) if x.strip() == f"<{tag}>".lower()]
    if not starts:
        return None
    ends = [(i, x) for i, x in enumerate(lines) if x.strip() == f"</{tag}>".lower()]
    if ends:
        start = sum(len(l) for l in lines[:starts[0][0]+1])
        end = sum(len(l) for l in lines[:ends[0][0]])
        return start+skip, end+skip
    # don't use start tag as ending in clean mode
    return None

def parse_fields(content: str, model: type[BaseModel]) -> dict[str, Any]:
    res: dict[str, Any] = {}
    for field_name, field in model.model_fields.items():
        # type of the field can be: list[x], Optional[x], x
        is_list = False
        t = None
        match get_origin(field.annotation), get_args(field.annotation):
            case (origin, (t, o)) if origin is Union and o is type(None):
                pass
            case (origin, (t, )) if origin is list:
                is_list = True
            case _:
                t = field.annotation

        if is_list:
            res[field_name] = []

        offset = 0
        while offset + len(field_name) < len(content):
            # if we have a full match
            if bounds := (
                tag_start_end_clean(content.lower(), field_name, offset) or
                tag_start_end(content.lower(), field_name, offset)
            ):
                enclosed: Any = content[bounds[0]:bounds[1]].strip()

                # if the child is supposed to be a model
                if isinstance(t, type) and issubclass(t, BaseModel):
                    enclosed = parse_fields(enclosed, t)

                # if this is a list
                if is_list:
                    res[field_name].append(enclosed)
                else:
                    res[field_name] = enclosed

                offset = bounds[1]+1
            else:
                break
    return res

def describe_field_type(schema: dict[str, Any], field: dict[str, Any], nested_ok:bool=True, s:str = "") -> str:
    # something like a union, which we'll assume is with null
    if 'anyOf' in field:
        assert field.get("default") is None
        assert len(field['anyOf']) == 2
        t, = [x for x in field['anyOf'] if x.get("type") != "null"]
        return "optional " + describe_field_type(schema, t, nested_ok=nested_ok)
    elif field.get("type") == "array":
        return (
          f"optional and repeatable {describe_field_type(schema, field.get('items', {}), nested_ok=nested_ok, s='s')}. "
          "Include this field ONLY IF NEEDED"
        )
    elif ref := field.get("$ref"):
        assert nested_ok, "only 1 level of model nesting allowed"
        defs = schema.get("$defs")
        assert isinstance(defs, dict)
        defs = cast(dict[str, Any], defs)
        defin =  defs.get(ref.split("/")[-1])
        assert defin
        return f"nested object{s} with fields\n" + describe_model(defin, " - ", nested_ok=False)
    else:
        return cast(str, field.get("type", "string")) + s

def describe_model(schema: dict[str, Any], indent:str="", nested_ok:bool=True) -> str:
    assert "properties" in schema, "no top-level properties in schema? (recursive models not supported)"
    content = ""
    for field_name, field in schema["properties"].items():
        content += (
            f'{indent}`<{field_name}>` : ({describe_field_type(schema, field, nested_ok=nested_ok)}) '
            f'{field.get("description", "")}\n'
        )
    return content

def recursive_search(schema: dict[Any, Any], sk: str, sv: Optional[str]=None) -> bool:
    for k, v in schema.items():
        if k == sk and ((v == sv) or (sv is None)):
            return True
        if isinstance(v, dict):
            if recursive_search(cast(dict[str, Any], v), sk, sv=sv):
                return True
    return False

def describe_errors(e: ValidationError, model: type[BaseModel]) -> str:
    content = "The output you provided failed to validate: "
    for error in e.errors():
        path = ".".join([str(x) for x in error.get("loc", [])])
        content += f"\n{error.get('msg', 'Error')}: {path}"
    content += (
        "\nNOTE: if you are not finished, you should make a tool call instead. "
        "If that's the case, be sure to call it correctly in your next message."
    )
    return content

def XMLVerifyClass[R: BaseModel](cls: type[R]) -> type[R]:
    _ = describe_model(cls.model_json_schema())

    for field_name, field in cls.model_fields.items():
        if get_origin(field.annotation) is list:
            assert field.is_required(), f"{field_name} is an optional list: not allowed!"
        if get_origin(field.annotation) is Union:
            assert all([get_origin(x) is not list for x in get_args(field.annotation)]), f"{field_name} is an optional list: not allowed!"
        for child in [field.annotation] + list(get_args(field.annotation)):
            if isinstance(child, type) and issubclass(child, BaseModel):
                _ = XMLVerifyClass(child)

    setattr(cls, XML_CHECKED_ATTRIBUTE, True)
    return cls

class XMLAgent[R: BaseModel](AgentGeneric[R]):
    @property
    @abstractmethod
    def return_type(self) -> type[R]:
        pass

    @property
    def tag_guidance(self) -> str:
        content = (
            "<output>\nDo not stop calling tools until you are finished with your task.\n"
            "When you are completely finished, provide output as plain XML with the structure AFTER your thoughts:\n"
        )
        content += describe_model(self.return_type.model_json_schema())
        if recursive_search(self.return_type.model_json_schema(), "anyOf"):
            content += "You may omit optional tags. "
        if recursive_search(self.return_type.model_json_schema(), "type", "array"):
            content += "For repeatable tags, you may use the tag 0 or more times, as many as needed. "
        content += (
            "ALWAYS put your explanations and thoughts BEFORE the XML tags. The XML tags should be the last thing "
            "that you output\n</output>"
        )
        return content

    def get_result(self, msg: Message) -> R | Message | None:
        # msg contains no tool call, no/incomplete tags -> add a message asking what's up
        # msg contains no tool call, tags -> stop; result = parse(tags)

        # nothing for us to do here
        assert msg.role == "assistant"
        if msg.tool_calls:
            return None

        if msg.content is None:
            return Message(role="user", content=self.tag_guidance)

        res = parse_fields(msg.content, self.return_type)
        try:
            return self.return_type.model_validate(res)
        except ValidationError as e:
            return Message(role="user", content=describe_errors(e, self.return_type))

    @property
    def init_msgs(self):
        return False

    def __init__(self) -> None:
        super().__init__()
        assert hasattr(self.return_type, XML_CHECKED_ATTRIBUTE), "models passed to XMLAgent must be verified using @XMLVerifyClass"
        system = f"{self.prompts.system}\n{self.tag_guidance}"
        self._append_msg(Message(role="system", content=system))
        self._append_msg(Message(role="user", content=self.prompts.user))
