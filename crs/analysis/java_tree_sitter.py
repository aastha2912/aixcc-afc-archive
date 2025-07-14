import tree_sitter
import tree_sitter_java

from .data import SourceFile, SourceClass, SourceFunction, SourceMember, SourceRange, node_range

lang = tree_sitter.Language(tree_sitter_java.language())
parser = tree_sitter.Parser(lang)

query = lang.query("""
([
  (package_declaration (scoped_identifier) @package.path) @package
  (import_declaration (scoped_identifier) @import.path) @import
  (line_comment) @comment
  (block_comment) @comment

  ; _ to match both class_declaration and interface_declaration
  ; not sure if this is sound
  (_
    (modifiers)? @class.modifiers
    name: (identifier) @class.name
    ; _ to match both class_body and interface_body
    body: (_
      ([
        ; modifiers are optional
        ; block is optional (abstract)
        (method_declaration
          (modifiers)? @func.modifiers
          type:       (_)                  @func.return_type
          name:       (identifier)         @func.name
          parameters: (formal_parameters)  @func.args
          body:       (block)?             @func.body
        ) @class.method

        (constructor_declaration
          name:       (identifier)         @func.name
          parameters: (formal_parameters)  @func.args
          body:       (constructor_body)?  @func.body
        ) @class.constructor

        ((block) @class.initializer)
        ((static_initializer (block) @class.static_initializer))

        (field_declaration
         (modifiers)? @field.modifiers
         type: (_) @field.type
         declarator: (_ (identifier) @field.name)
        ) @class.field
      ]) @class.member)
  ) @class.def
])
""")

name_query = lang.query("(identifier) @name")

param_query = lang.query("""
(formal_parameters
  (formal_parameter
     type: _ @type
     name: (identifier) @name) @param)
""")

def parse(sf: SourceFile) -> list[SourceMember]:
    tree = parser.parse(sf.source)

    def get_param_types(node: tree_sitter.Node) -> list[bytes]:
        types: list[bytes] = []
        for _, m in param_query.matches(node):
            match m:
                case {"name": [_name_node], "type": [type_node]}:
                    types.append(type_node.text or b"")
                case _: ...
        return types

    def containing_classes(node: tree_sitter.Node) -> list[tree_sitter.Node]:
        parents: list[tree_sitter.Node] = []
        while node.parent is not None:
            node = node.parent
            if node.type in ("class_declaration", "interface_declaration"):
                parents.append(node)
        parents.reverse()
        return parents

    decls: list[SourceMember] = []

    matches = query.matches(tree.root_node)
    for _, m in matches:
        parents = []
        class_prefix = b""
        match m:
            case {"class.def": [class_def],
                  "class.name": [class_name],
                  "class.member": [class_member]}:
                parents = containing_classes(class_def) + [class_def]
                parent_names: list[bytes] = []
                for node in parents:
                    parent_names.append(name_query.matches(node)[0][1]["name"][0].text or b"")
                class_prefix = b"::".join(name for name in parent_names)
            case _: ...

        # class definition (no "class.member" field)
        match m:
            case {"class.def": [class_def],
                  "class.name": [class_name],
                  "class.body": [class_body],
                  } if "class.member" not in m:
                decls.append(SourceClass(
                    name=class_name.text or b"",
                    fullname=b"::".join([class_prefix, class_name.text or b""]),
                    file=sf,
                    range=node_range(class_def),
                    body=node_range(class_body),
                ))
            case _: ...

        match m:
            # NOTE: package and import are not contained in a class
            case {"package.path": [_package_path]}:
                ...
                # TODO: this is sort of at the file level?
                # print("package", package_path.text.decode(errors="replace"))

            case {"import.path": [_import_path]}:
                ...
                # TODO: this is sort of at the file level?
                # print("import", import_path.text.decode(errors="replace"))

            # NOTE: duplicated from constructor
            # NOTE: it's possible to have a method and a constructor with the same name, need to disambiguate
            case {
                "class.constructor": [_class_constructor],
                "class.member": [class_member],
                "func.args": [func_args],
                "func.body": [func_body],
                "func.name": [func_name],
                "func.return_type": [func_return_type],
                # OPTIONAL: func.modifiers
            }:
                # TODO: mark as constructor?
                param_types = b", ".join(get_param_types(func_args))
                _overload_sig = (func_name.text or b"") + b"(" + param_types + b")"

                decls.append(SourceFunction(
                    name=func_name.text or b"",
                    fullname=b"::".join([class_prefix, func_name.text or b""]),
                    file=sf,
                    range=node_range(class_member),
                    body=node_range(func_body), # TODO: body is optional for abstract methods
                    sig=SourceRange(class_member.start_byte, func_body.start_byte),
                    args=node_range(func_args),
                    return_type=node_range(func_return_type),
                    # TODO: modifiers
                ))

            # NOTE: duplicated from constructor
            case {
                "class.method": [_class_method],
                "class.member": [class_member],
                "func.args": [func_args],
                "func.body": [func_body],
                "func.name": [func_name],
                "func.return_type": [func_return_type],
                # OPTIONAL: func.modifiers
            }:
                # TODO: mark as method?
                param_types = b", ".join(get_param_types(func_args))
                _overload_sig = (func_name.text or b"") + b"(" + param_types + b")"

                decls.append(SourceFunction(
                    name=func_name.text or b"",
                    fullname=b"::".join([class_prefix, func_name.text or b""]),
                    file=sf,
                    range=node_range(class_member),
                    body=node_range(func_body), # TODO: body is optional for abstract methods
                    sig=SourceRange(class_member.start_byte, func_body.start_byte),
                    args=node_range(func_args),
                    return_type=node_range(func_return_type),
                    # TODO: modifiers
                ))

            case {
                "class.field": [_field_def],
                "field.type": [_field_type],
                "field.name": [_field_name],
                # OPTIONAL field.modifiers
            }:
                ...
                # TODO: unused
                # print("field", field_type.text, field_name.text)

            case {"class.initializer": [block], "class.member": [class_member]}:
                decls.append(SourceFunction(
                    name=b"{}",
                    fullname=b"::".join([class_prefix, b"{}"]),
                    file=sf,
                    range=node_range(class_member),
                    body=node_range(block),
                    sig=SourceRange(block.start_byte, block.start_byte),
                    args=SourceRange(block.start_byte, block.start_byte),
                    return_type=SourceRange(block.start_byte, block.start_byte),
                ))

            # TODO: annotate as static?
            case {"class.static_initializer": [block], "class.member": [class_member]}:
                decls.append(SourceFunction(
                    name=b"static{}",
                    fullname=b"::".join([class_prefix, b"static{}"]),
                    file=sf,
                    range=node_range(class_member),
                    body=node_range(block),
                    sig=SourceRange(block.start_byte, block.start_byte),
                    args=SourceRange(block.start_byte, block.start_byte),
                    return_type=SourceRange(block.start_byte, block.start_byte),
                ))

            case {"comment": _}:
                ...

            # NOTE other should be unreachable if you update the match when you update the query
            case _:
                ...

    return decls

if __name__ == "__main__":
    import sys
    for path in sys.argv[1:]:
        with open(path, "rb") as f:
            data = f.read()
        sf = SourceFile(path, data)
        for member in parse(sf):
            print(member)
