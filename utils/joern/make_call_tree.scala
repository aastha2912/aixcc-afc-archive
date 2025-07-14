import io.shiftleft.semanticcpg.language._
import scala.collection.mutable
import upickle.default._

def findPathToFuzzerTestOneInput(
    startMethod: nodes.Method,
    begin_name: String,
    begin_file: String,
    maxDepth: Int = 20,
): List[nodes.Method] = {
  val visited = mutable.Set[nodes.Method]()
  val queue = new mutable.Queue[List[nodes.Method]]()

  queue.enqueue(List(startMethod))
  visited += startMethod

  while (queue.nonEmpty) {
    val currentPath = queue.dequeue()
    val lastMethod = currentPath.last

    if (lastMethod.name == begin_name && lastMethod.filename == begin_file) {
      return currentPath
    }

    if (currentPath.size < maxDepth) {
      val callers = lastMethod.caller.l
      for (callerMethod <- callers) {
        if (!visited.contains(callerMethod)) {
          visited += callerMethod
          queue.enqueue(currentPath :+ callerMethod)
        }
      }
    }
  }
  List.empty
}

@main def exec(project_path:String, begin_name:String, begin_file:String, target_name:String, target_file:String, maxDepth:Int = 20) = {
    importCode(project_path)

    val targetList = List((target_name,target_file))
    val checkBeginMethods = cpg.method.name(begin_name).filename(begin_file).l
    if (checkBeginMethods.isEmpty) {
      println("begin empty")
    }
    else if (checkBeginMethods.size != 1){
      println("begin many")
    }
    else {
      for ((targetName, targetFile) <- targetList) {
          val candidateMethods = cpg.method.name(targetName).filename(targetFile).l
          if (candidateMethods.isEmpty) {
            println("target empty")
          } else if (candidateMethods.size != 1) {
            println("target many")
          }
          else {
          for (m <- candidateMethods) {
              val path = findPathToFuzzerTestOneInput(m, begin_name=begin_name, begin_file=begin_file, maxDepth=maxDepth)
              if (path.size == 0){
                println("no result")
              } else {
                val result = path.map(call => (call.name, call.method.filename, call.method.code, call.method.lineNumber)).l.toJson
              println(result)
            }
          }
        }
      }
    }
  }