/*
 * JS/TS taint queries for ai-codescan.
 *
 * Run as:
 *   joern --script ai_codescan/engines/joern_queries.sc \
 *         --param cpgPath=<path>.cpg.bin \
 *         --param outPath=<path>.jsonl
 *
 * Emits one JSONL record per source→sink flow with:
 *   {fid, source_file, source_line, sink_file, sink_line, source_name,
 *    sink_name, cwe, sink_class, parameterization}
 *
 * Coverage today:
 *   - sqli (CWE-89): req.* → *.query / *.execute
 *   - cmdi (CWE-78): req.* → shell-spawning APIs
 *   - xss  (CWE-79): req.* → res.send / res.write / res.end
 *   - path-traversal (CWE-22): req.* → fs.readFile / fs.createReadStream
 *
 * Strategy: Joern's interprocedural data-flow engine via reachableByFlows.
 * For each sink call, we ask the engine "is any source reachable to this
 * call's argument?". A non-empty path means a real def→use chain exists,
 * which catches handler→helper→sink relays that the prior co-location
 * heuristic could not reach.
 *
 * The co-location fallback is retained for cases where the engine returns
 * no paths (e.g. the JS frontend produced a CPG without sufficient AST
 * resolution for closure-captured handlers); cross-engine dedupe collapses
 * any double-reporting against CodeQL/Semgrep.
 */

import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import java.io.{FileWriter, BufferedWriter}
import java.security.MessageDigest

@main def execScan(cpgPath: String, outPath: String, language: String = "javascript") = {
  importCpg(cpgPath)

  implicit val engineCtx: EngineContext = EngineContext()

  // Source/sink patterns are language-specific. Both the JS and pythonsrc
  // frontends store `call.name` as the bare method name (e.g. "query",
  // "execute"); receiver context is implicit in the data-flow path.
  case class LangPatterns(
    sourcePattern: String,
    sinkClasses: List[(String, String, String)]
  )

  val patterns: LangPatterns = language.toLowerCase match {
    case "python" =>
      LangPatterns(
        sourcePattern =
          "(?i)(request\\.args|request\\.form|request\\.json|request\\.values|" +
          "request\\.data|request\\.cookies|request\\.headers|request\\.files|" +
          "request\\.GET|request\\.POST|request\\.body|request\\.COOKIES|" +
          "request\\.META|sys\\.argv).*",
        sinkClasses = List(
          ("CWE-89",  "sql.exec",      "(?i)execute"),
          ("CWE-89",  "sql.exec",      "(?i)executemany"),
          ("CWE-78",  "cmd.shell",     "(?i)(system|popen|check_output|check_call|Popen)"),
          ("CWE-78",  "cmd.shell",     "(?i)(eval)"),
          ("CWE-79",  "html.write",    "(?i)render_template_string"),
          ("CWE-79",  "html.write",    "(?i)(Markup|mark_safe)"),
          ("CWE-22",  "fs.read",       "(?i)open"),
          ("CWE-502", "deser.unsafe",  "(?i)loads"),
          ("CWE-502", "deser.unsafe",  "(?i)(load|full_load|unsafe_load)")
        )
      )
    case _ =>
      val ce = "exec"
      val cs = "spawn"
      LangPatterns(
        sourcePattern = "(?i)(req\\.body|req\\.query|req\\.params|process\\.argv).*",
        sinkClasses = List(
          ("CWE-89", "sql.exec",   "(?i)query"),
          ("CWE-89", "sql.exec",   "(?i)execute"),
          ("CWE-78", "cmd.shell",  s"(?i)${ce}(Sync)?"),
          ("CWE-78", "cmd.shell",  s"(?i)${cs}(Sync)?"),
          ("CWE-79", "html.write", "(?i)(send|write|end)"),
          ("CWE-22", "fs.read",    "(?i)(readFile|createReadStream|readFileSync)")
        )
      )
  }
  val sourceNamePattern = patterns.sourcePattern
  val sinkClasses = patterns.sinkClasses

  def sha1Short(s: String): String = {
    val md = MessageDigest.getInstance("SHA-1")
    md.update(s.getBytes("UTF-8"))
    md.digest().take(8).map("%02x".format(_)).mkString
  }

  def escape(s: String): String =
    s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r")

  case class SourceLoc(file: String, line: Int, code: String)

  def fileOf[A <: io.shiftleft.codepropertygraph.generated.nodes.AstNode](n: A): String = {
    val files: List[String] = n.file.name.l
    if (files.nonEmpty) files.head else ""
  }
  def lineOf[A <: io.shiftleft.codepropertygraph.generated.nodes.AstNode](n: A): Int = {
    val lines = n.lineNumber.l
    if (lines.nonEmpty) lines.head.toString.toInt else 0
  }

  // Pre-compute sources once for both flow-engine queries and the fallback.
  val rawSources = cpg.fieldAccess.code(sourceNamePattern).l ++
                   cpg.identifier.name(sourceNamePattern).l

  val sourcesByFile = scala.collection.mutable.HashMap.empty[String, List[SourceLoc]]
  rawSources.foreach { node =>
    val f = fileOf(node)
    if (f.length > 0) {
      val info = SourceLoc(f, lineOf(node), node.code)
      val existing: List[SourceLoc] = sourcesByFile.getOrElse(f, Nil)
      sourcesByFile.put(f, info :: existing)
    }
  }

  val MAX_DISTANCE_LINES = 200

  // Track (file, line, cwe) tuples already emitted so the fallback does not
  // double-report a flow that the data-flow engine already produced.
  val emitted = scala.collection.mutable.HashSet.empty[(String, Int, String, Int, String)]

  val w = new BufferedWriter(new FileWriter(outPath))
  try {
    for ((cwe, sinkClass, sinkPattern) <- sinkClasses) {
      val sinkCalls = cpg.call.name(sinkPattern).l

      // ---- Pass 1: reachableByFlows on each sink's arguments ----
      for (call <- sinkCalls) {
        val sinkFile = fileOf(call)
        val sinkLine = lineOf(call)
        val args = call.argument.l
        val paths =
          try args.reachableByFlows(rawSources).l
          catch { case _: Throwable => Nil }
        for (path <- paths if path.elements.nonEmpty) {
          val srcNode = path.elements.head
          val srcFile = fileOf(srcNode)
          val srcLine = lineOf(srcNode)
          val srcCode = srcNode.code
          val key = (srcFile, srcLine, sinkFile, sinkLine, cwe)
          if (!emitted.contains(key)) {
            emitted.add(key)
            val fid = "joern-" + sha1Short(s"$srcFile:$srcLine:$sinkFile:$sinkLine:$cwe")
            val js =
              s"""{"fid":"$fid","source_file":"${escape(srcFile)}",""" +
              s""""source_line":$srcLine,"sink_file":"${escape(sinkFile)}",""" +
              s""""sink_line":$sinkLine,"source_name":"${escape(srcCode)}",""" +
              s""""sink_name":"${escape(call.name)}","cwe":"$cwe",""" +
              s""""sink_class":"$sinkClass","parameterization":"unknown"}"""
            w.write(js)
            w.newLine()
          }
        }
      }

      // ---- Pass 2: co-location fallback for sinks the engine missed ----
      for (sink <- sinkCalls) {
        val sinkFile = fileOf(sink)
        val sinkLine = lineOf(sink)
        val candidates: List[SourceLoc] = sourcesByFile.getOrElse(sinkFile, Nil)
        val nearby = candidates.filter(s => Math.abs(sinkLine - s.line) <= MAX_DISTANCE_LINES)
        if (nearby.nonEmpty) {
          val src = nearby.minBy(s => Math.abs(sinkLine - s.line))
          val key = (src.file, src.line, sinkFile, sinkLine, cwe)
          if (!emitted.contains(key)) {
            emitted.add(key)
            val fid = "joern-" + sha1Short(s"${src.file}:${src.line}:$sinkFile:$sinkLine:$cwe")
            val js =
              s"""{"fid":"$fid","source_file":"${escape(src.file)}",""" +
              s""""source_line":${src.line},"sink_file":"${escape(sinkFile)}",""" +
              s""""sink_line":$sinkLine,"source_name":"${escape(src.code)}",""" +
              s""""sink_name":"${escape(sink.name)}","cwe":"$cwe",""" +
              s""""sink_class":"$sinkClass","parameterization":"unknown"}"""
            w.write(js)
            w.newLine()
          }
        }
      }
    }
  } finally {
    w.close()
  }
}
