def output(line: String) = {
    println("OUTPUT: " + line)
}

def find_lines(name: String) = {
    for (line <- cpg.method
        .filter(node => !node.isExternal && node.name == name)
        .map(node => s"${node.filename},${node.lineNumber.get},${node.lineNumberEnd.get}")) {
        output(line)
    }
    for (line <- cpg.typeDecl
        .filter(node => !node.isExternal && node.name == name)
        .map(node => s"${node.filename},${node.lineNumber.get},-1")) {
        output(line)
    }
}
