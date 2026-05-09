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

  // Source/sink patterns are language-specific. The JS, pythonsrc, and
  // javasrc frontends all expose ``call.name`` as the bare method name
  // (``query`` / ``execute`` / ``executeQuery`` etc.); receiver and class
  // context show up via ``methodFullName``, but we lean on bare-name
  // patterns for portability and rely on the data-flow engine + cross-engine
  // dedupe to suppress false positives.
  case class LangPatterns(
    sourcePattern: String,
    sinkClasses: List[(String, String, String)]
  )

  val patterns: LangPatterns = language.toLowerCase match {
    case "ruby" | "rubysrc" =>
      LangPatterns(
        sourcePattern =
          "(?i)(params|request\\.params|request\\.body|request\\.GET|" +
          "request\\.POST|request\\.cookies|request\\.headers|" +
          "session|cookies|env).*",
        sinkClasses = List(
          ("CWE-89",  "sql.exec",      "(?i)where"),
          ("CWE-89",  "sql.exec",      "(?i)find_by_sql"),
          ("CWE-89",  "sql.exec",      "(?i)exec_query"),
          ("CWE-89",  "sql.exec",      "(?i)execute"),
          ("CWE-89",  "sql.exec",      "(?i)select_all"),
          ("CWE-78",  "cmd.shell",     "(?i)system"),
          ("CWE-78",  "cmd.shell",     "(?i)spawn"),
          ("CWE-78",  "cmd.shell",     "(?i)popen"),
          ("CWE-78",  "cmd.shell",     "(?i)Open3"),
          ("CWE-79",  "html.write",    "(?i)html_safe"),
          ("CWE-79",  "html.write",    "(?i)raw"),
          ("CWE-22",  "fs.read",       "(?i)read"),
          ("CWE-22",  "fs.read",       "(?i)open"),
          ("CWE-22",  "fs.read",       "(?i)binread"),
          ("CWE-502", "deser.unsafe",  "(?i)load"),
          ("CWE-502", "deser.unsafe",  "(?i)restore"),
          ("CWE-94",  "code.exec",     "(?i)eval"),
          ("CWE-94",  "code.exec",     "(?i)instance_eval"),
          ("CWE-94",  "code.exec",     "(?i)class_eval")
        )
      )
    case "go" | "golang" =>
      LangPatterns(
        sourcePattern =
          "(?i)(c\\.Query|c\\.QueryArray|c\\.PostForm|c\\.GetHeader|c\\.Param|" +
          "c\\.GetRawData|c\\.FormValue|c\\.Cookie|" +
          "ctx\\.Query|ctx\\.QueryParam|ctx\\.FormValue|ctx\\.Param|" +
          "ctx\\.Cookie|ctx\\.Header|ctx\\.Body|" +
          "r\\.URL\\.Query|r\\.FormValue|r\\.PostFormValue|r\\.Header\\.Get|" +
          "r\\.Cookie|r\\.Body).*",
        sinkClasses = List(
          ("CWE-89",  "sql.exec",      "(?i)Exec"),
          ("CWE-89",  "sql.exec",      "(?i)Query"),
          ("CWE-89",  "sql.exec",      "(?i)QueryRow"),
          ("CWE-89",  "sql.exec",      "(?i)Prepare"),
          ("CWE-89",  "sql.exec",      "(?i)Raw"),
          ("CWE-78",  "cmd.shell",     "(?i)Command"),
          ("CWE-78",  "cmd.shell",     "(?i)CommandContext"),
          ("CWE-79",  "html.write",    "(?i)Fprint"),
          ("CWE-79",  "html.write",    "(?i)Fprintln"),
          ("CWE-79",  "html.write",    "(?i)Fprintf"),
          ("CWE-22",  "fs.read",       "(?i)Open"),
          ("CWE-22",  "fs.read",       "(?i)OpenFile"),
          ("CWE-22",  "fs.read",       "(?i)ReadFile"),
          ("CWE-502", "deser.unsafe",  "(?i)Decode"),
          ("CWE-502", "deser.unsafe",  "(?i)Unmarshal")
        )
      )
    case "java" =>
      LangPatterns(
        sourcePattern =
          "(?i)(getParameter|getQueryString|getHeader|getInputStream|" +
          "getReader|getRequestURI|getCookies|getRemoteUser|getPathInfo|" +
          "getServletPath|getRequestURL|getQueryParam|getPathParam|" +
          "getHeaderString|getFormParam|RequestParam|RequestBody|" +
          "PathVariable|RequestHeader).*",
        sinkClasses = List(
          ("CWE-89",  "sql.exec",      "(?i)executeQuery"),
          ("CWE-89",  "sql.exec",      "(?i)executeUpdate"),
          ("CWE-89",  "sql.exec",      "(?i)prepareStatement"),
          ("CWE-89",  "sql.exec",      "(?i)createQuery"),
          ("CWE-89",  "sql.exec",      "(?i)createNativeQuery"),
          ("CWE-89",  "sql.exec",      "(?i)queryForList"),
          ("CWE-89",  "sql.exec",      "(?i)queryForObject"),
          ("CWE-78",  "cmd.shell",     "(?i)exec"),
          ("CWE-78",  "cmd.shell",     "(?i)ProcessBuilder"),
          ("CWE-79",  "html.write",    "(?i)println"),
          ("CWE-79",  "html.write",    "(?i)getWriter"),
          ("CWE-79",  "html.write",    "(?i)addAttribute"),
          ("CWE-22",  "fs.read",       "(?i)FileInputStream"),
          ("CWE-22",  "fs.read",       "(?i)newInputStream"),
          ("CWE-22",  "fs.read",       "(?i)newBufferedReader"),
          ("CWE-22",  "fs.read",       "(?i)readAllBytes"),
          ("CWE-502", "deser.unsafe",  "(?i)readObject"),
          ("CWE-502", "deser.unsafe",  "(?i)deserialize")
        )
      )
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
  // Java's request-borne data flows through method parameters that carry
  // annotations like @RequestParam / @RequestBody / @PathVariable rather
  // than top-level field reads, so for Java we additionally include matching
  // parameter nodes (their ``code`` includes the annotation text).
  val baseRawSources = cpg.fieldAccess.code(sourceNamePattern).l ++
                       cpg.identifier.name(sourceNamePattern).l
  val srcRegex = sourceNamePattern.r
  val rawSources =
    if (language.toLowerCase == "java") {
      val javaParamSources =
        cpg.parameter
          .filter(p => p.code != null && srcRegex.findFirstIn(p.code).isDefined)
          .l
      baseRawSources ++ javaParamSources
    } else if (language.toLowerCase == "go" || language.toLowerCase == "golang") {
      // Go's request data lands via method calls on the request/context
      // object (``c.Query("id")``, ``r.URL.Query()``); the *call result* is
      // the taint source, so include matching call nodes alongside
      // identifier/fieldAccess reads.
      val goCallSources = cpg.call.code(sourceNamePattern).l
      baseRawSources ++ goCallSources
    } else baseRawSources

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

  // Track (src_file, src_line, sink_file, sink_line, cwe) tuples already
  // emitted so the fallback does not double-report a flow that the data-flow
  // engine already produced. The per-sink set lets the co-location fallback
  // run only for sinks the engine couldn't link to *any* source.
  val emitted = scala.collection.mutable.HashSet.empty[(String, Int, String, Int, String)]
  val pass1HitSinks = scala.collection.mutable.HashSet.empty[(String, Int, String)]

  // For JS XSS sinks the bare-name pattern (?i)(send|write|end) over-matches —
  // it picks up Promise.end, Array.send, Stream.write etc. Filter the sink set
  // by receiver text (``res.``, ``response.``, ``reply.``, ``ctx.``) for the
  // JS XSS class to cut FPs without disturbing the generic match flow.
  val xssReceiver = """(?is).*\b(?:res|response|reply|ctx)\.(?:send|write|end)\b.*""".r
  def restrictXssSinks(
    cwe: String,
    sinks: List[io.shiftleft.codepropertygraph.generated.nodes.Call]
  ): List[io.shiftleft.codepropertygraph.generated.nodes.Call] = {
    if (cwe == "CWE-79" && language.toLowerCase != "python") {
      sinks.filter { c =>
        val code = if (c.code != null) c.code else ""
        xssReceiver.matches(code)
      }
    } else sinks
  }

  val w = new BufferedWriter(new FileWriter(outPath))
  try {
    for ((cwe, sinkClass, sinkPattern) <- sinkClasses) {
      val sinkCalls = restrictXssSinks(cwe, cpg.call.name(sinkPattern).l)

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
          // Suppress self-loops: when a source and a sink share the exact
          // same file+line they're almost certainly the same call (e.g.
          // ``c.Query("id")`` matched as both a Go request source and a
          // ``Query`` SQL sink). Real flows always cross at least one line.
          if (srcFile == sinkFile && srcLine == sinkLine) {
            // skip — self-loop
          } else {
            val key = (srcFile, srcLine, sinkFile, sinkLine, cwe)
            if (!emitted.contains(key)) {
              emitted.add(key)
              pass1HitSinks.add((sinkFile, sinkLine, cwe))
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
      }

      // ---- Pass 2: co-location fallback for sinks Pass 1 missed entirely ----
      // The fallback exists for closure-captured JS handlers where def/use
      // links are weak. For Python, Java, and Go the data-flow engine is
      // mature enough that the heuristic produces more noise than signal —
      // gate the fallback on JS only.
      val fallbackEnabled = language.toLowerCase != "python" &&
                            language.toLowerCase != "java" &&
                            language.toLowerCase != "go" &&
                            language.toLowerCase != "golang"
      for (sink <- sinkCalls if fallbackEnabled) {
        val sinkFile = fileOf(sink)
        val sinkLine = lineOf(sink)
        if (pass1HitSinks.contains((sinkFile, sinkLine, cwe))) {
          // already covered by data-flow engine; don't fall back
        } else {
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
        }  // end else (pass1 didn't cover this sink)
      }
    }
  } finally {
    w.close()
  }
}
