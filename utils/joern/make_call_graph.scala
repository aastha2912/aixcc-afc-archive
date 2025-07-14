import ujson._

val callGraphJson = Obj()
cpg.method.foreach { m =>
// Gather method info
val startLine = m.lineNumber.getOrElse(-1)
val endLine   = m.lineNumberEnd.getOrElse(-1)
// Build the key, e.g. "foo.c:my_namespace::myMethod"
val key = s"${m.filename}:$startLine:$endLine:${m.name}"
// Create the "callees" array
val callees = m.callee.filter(c => c.code != "<empty>").l.map { callee =>
    s"${callee.filename}:${callee.lineNumber.getOrElse(-1)}:${callee.lineNumberEnd.getOrElse(-1)}:${callee.name}"
}
// Build a ujson object for this method
val methodObj = Obj(
    "source"     -> m.filename,
    "start_line" -> startLine,
    "end_line"   -> endLine,
    "callees"    -> Arr.from(callees)
)
// Insert into the callGraphJson under the given key
callGraphJson(key) = methodObj
}
println("OUTPUT: " + callGraphJson.render(indent = -1))