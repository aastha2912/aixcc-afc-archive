import tree_sitter
import tree_sitter_c

from .data import SourceFile, SourceMember, SourceFunction, SourceRange, node_range

lang = tree_sitter.Language(tree_sitter_c.language())
parser = tree_sitter.Parser(lang)

# TODO: handle macros and top-level statements?
query = lang.query("""
(
  function_definition
    type: (_) @func.return_type
    declarator: [
      (function_declarator
        declarator: (identifier) @func.name
        parameters: (parameter_list) @func.args)
      (pointer_declarator
        declarator: (function_declarator
          declarator: (identifier) @func.name
          parameters: (parameter_list) @func.args))
    ]
    body: (compound_statement) @func.body
) @func.def
""")

def parse(sf: SourceFile) -> list[SourceMember]:
    tree = parser.parse(sf.source)

    decls: list[SourceMember] = []

    functions = query.matches(tree.root_node)
    for _, func in functions:
        match func:
            case {
                "func.def": [func_def],
                "func.return_type": [func_return_type],
                "func.name": [func_name],
                "func.args": [func_args],
                "func.body": [func_body],
            }:
                source_fn = SourceFunction(
                    name=func_name.text or b"",
                    fullname=func_name.text or b"",
                    file=sf,
                    range=node_range(func_def),
                    sig=SourceRange(
                        func_return_type.start_byte,
                        func_args.end_byte,
                    ),
                    args=node_range(func_args),
                    return_type=node_range(func_return_type),
                    body=node_range(func_body)
                )
                decls.append(source_fn)
            case _:
                # TODO: failed to match?
                pass
    return decls

if __name__ == "__main__":
    import sys
    for path in sys.argv[1:]:
        with open(path, "rb") as f:
            data = f.read()
        sf = SourceFile(path, data)
        for member in parse(sf):
            print(member)
