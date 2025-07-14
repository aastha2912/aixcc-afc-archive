import ujson._

val funcs = ujson.Arr()
cpg.method.foreach { m =>
// Gather method info
    val startLine = m.lineNumber.getOrElse(-1)
    val endLine   = m.lineNumberEnd.getOrElse(-1)
    if (!m.isExternal && startLine != -1 && endLine != -1) {
        funcs.value.append(Obj(
            "name" -> m.name,
            "source" -> m.filename,
            "start_line" -> startLine,
            "end_line"   -> endLine,
            "code" -> m.code,
        ))
    }
}
val typeDecls = ujson.Arr()
cpg.typeDecl.foreach { m =>
// Gather typeDecl info
    val startLine = m.lineNumber.getOrElse(-1)
    if (!m.isExternal && startLine != -1) {
        typeDecls.value.append(Obj(
            "name" -> m.name,
            "source" -> m.filename,
            "start_line" -> startLine,
        ))
    }
}
println("OUTPUT: " + Obj("funcs" -> funcs, "types" -> typeDecls).render(indent = -1))