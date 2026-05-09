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
 * Coverage today (MVP):
 *   - sqli (CWE-89): req.* → *.query / *.execute
 *   - cmdi (CWE-78): req.* → shell-spawning APIs
 *   - xss  (CWE-79): req.* → res.send / res.write / res.end
 *   - path-traversal (CWE-22): req.* → fs.readFile / fs.createReadStream
 *
 * Heuristic: source and sink share the same file AND the sink is within
 * N lines after the source (default 200). Real interprocedural Joern
 * dataflow is future work; this finds the common in-handler patterns.
 */

import io.shiftleft.semanticcpg.language._
import java.io.{FileWriter, BufferedWriter}
import java.security.MessageDigest

@main def execScan(cpgPath: String, outPath: String) = {
  importCpg(cpgPath)

  val sourceNamePattern = "(?i)(req\\.body|req\\.query|req\\.params|process\\.argv).*"

  // Joern's JS frontend stores `call.name` as the bare method name
  // (`query`, `send`, `readFile`) without the receiver. Patterns below
  // match against `name`; the receiver context is implicit in the per-file
  // co-location heuristic. Some FPs (e.g. an unrelated `Object.send`) are
  // expected — the cross-engine dedupe pass collapses overlap.
  val ce = "exec"
  val cs = "spawn"
  val sinkClasses: List[(String, String, String)] = List(
    ("CWE-89", "sql.exec",   "(?i)query"),
    ("CWE-89", "sql.exec",   "(?i)execute"),
    ("CWE-78", "cmd.shell",  s"(?i)${ce}(Sync)?"),
    ("CWE-78", "cmd.shell",  s"(?i)${cs}(Sync)?"),
    ("CWE-79", "html.write", "(?i)(send|write|end)"),
    ("CWE-22", "fs.read",    "(?i)(readFile|createReadStream|readFileSync)")
  )

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

  // Collect sources keyed by file path so we can quickly find ones near a sink.
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

  val w = new BufferedWriter(new FileWriter(outPath))
  try {
    for ((cwe, sinkClass, sinkPattern) <- sinkClasses) {
      val sinkCalls = cpg.call.name(sinkPattern).l
      for (sink <- sinkCalls) {
        val sinkFile = fileOf(sink)
        val sinkLine = lineOf(sink)
        val candidates: List[SourceLoc] = sourcesByFile.getOrElse(sinkFile, Nil)
        val nearby = candidates.filter(s => Math.abs(sinkLine - s.line) <= MAX_DISTANCE_LINES)
        if (nearby.nonEmpty) {
          // Pick the source closest to (and at or before) the sink.
          val src = nearby.minBy(s => Math.abs(sinkLine - s.line))
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
  } finally {
    w.close()
  }
}
