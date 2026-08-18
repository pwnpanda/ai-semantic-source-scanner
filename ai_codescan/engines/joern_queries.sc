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
 *   - xss  (CWE-79): req.* → res.send / res.write / res.end, plus DOM
 *                    sinks (innerHTML / eval / setTimeout) and stored-XSS
 *                    via the storage_taint fixpoint (Phase 16 / 17)
 *   - path-traversal (CWE-22): req.* → fs.readFile / fs.createReadStream
 *   - open redirect (CWE-601): req.* → res.redirect / sendRedirect / etc.
 *   - SSTI (CWE-1336): req.* → render_template_string (template arg)
 *   - email/CRLF injection (CWE-93): req.* → mailer.send / SMTP fields
 *   - CSPT (CWE-22, cspt): client-side path-section URL concat (Phase 19)
 *   - XXE (CWE-611): req.* → XML parse entry points (Phase 20)
 *   - prototype pollution (CWE-1321): req.body → deep-merge helpers
 *   - response splitting (CWE-93, header.write): req.* → setHeader/addHeader
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
    case "kotlin" =>
      // Kotlin source patterns — Spring on Kotlin reuses Java's
      // @RequestParam / @RequestBody / @PathVariable; Ktor's request DSL
      // exposes data through ``call.parameters[...]`` and
      // ``call.receive<T>()``. JDBC sinks are the same Java
      // executeQuery / executeUpdate / Statement / PreparedStatement
      // surface that javasrc2cpg sees.
      LangPatterns(
        sourcePattern =
          "(?i)(call\\.parameters|call\\.receive|call\\.request\\.queryParameters|" +
          "call\\.request\\.headers|RequestParam|RequestBody|PathVariable|" +
          "RequestHeader).*",
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
          ("CWE-79",  "html.write",    "(?i)respondText"),
          ("CWE-79",  "html.write",    "(?i)respondHtml"),
          ("CWE-22",  "fs.read",       "(?i)FileInputStream"),
          ("CWE-22",  "fs.read",       "(?i)newInputStream"),
          ("CWE-22",  "fs.read",       "(?i)readBytes"),
          ("CWE-22",  "fs.read",       "(?i)readText"),
          ("CWE-502", "deser.unsafe",  "(?i)readObject"),
          // Open redirect — Spring on Kotlin reuses Java's HttpServletResponse.
          ("CWE-601", "open.redirect", "(?i)^sendRedirect$"),
          // Phase 20 — XXE + response splitting; Kotlin reuses the Java stack.
          ("CWE-611", "xml.parse",     "(?i)^(parse|unmarshal|read)$"),
          ("CWE-611", "xml.parse",     "(?i)^(newDocumentBuilder|newSAXParser|createXMLStreamReader)$"),
          ("CWE-93",  "header.write",  "(?i)^(setHeader|addHeader|addCookie)$"),
          // Phase 21 — logging / SSTI / LDAP / XPath; same JVM libraries as Java.
          ("CWE-532", "log.sensitive", "(?i)^(trace|debug|info|warn|error|fatal|severe)$"),
          ("CWE-1336", "ssti",         "(?i)^(evaluate|<init>)$"),
          ("CWE-90",  "ldap.query",    "(?i)^search$"),
          ("CWE-643", "xpath.query",   "(?i)^(evaluate|compile|evaluateExpression|compileExpression|selectNodes|selectSingleNode)$")
        )
      )
    case "csharp" | "csharpsrc" =>
      LangPatterns(
        sourcePattern =
          "(?i)(HttpContext\\.Request|Request\\.Query|Request\\.Form|" +
          "Request\\.Headers|Request\\.Body|Request\\.Cookies|Request\\.RouteValues|" +
          "FromBody|FromQuery|FromRoute|FromForm|FromHeader|" +
          "QueryString|HttpRequest).*",
        sinkClasses = List(
          ("CWE-89",  "sql.exec",      "(?i)ExecuteNonQuery"),
          ("CWE-89",  "sql.exec",      "(?i)ExecuteScalar"),
          ("CWE-89",  "sql.exec",      "(?i)ExecuteReader"),
          ("CWE-89",  "sql.exec",      "(?i)ExecuteSqlRaw"),
          ("CWE-89",  "sql.exec",      "(?i)FromSqlRaw"),
          ("CWE-89",  "sql.exec",      "(?i)Query"),
          ("CWE-89",  "sql.exec",      "(?i)QueryAsync"),
          ("CWE-89",  "sql.exec",      "(?i)Execute"),
          ("CWE-78",  "cmd.shell",     "(?i)Start"),
          ("CWE-79",  "html.write",    "(?i)WriteAsync"),
          ("CWE-79",  "html.write",    "(?i)Write"),
          // Razor / MVC: ``@Html.Raw(x)`` and ``new HtmlString(x)`` both
          // explicitly opt out of the template engine's auto-escaping.
          ("CWE-79",  "html.write",    "(?i)^Raw$"),
          ("CWE-79",  "html.write",    "(?i)^HtmlString$"),
          ("CWE-22",  "fs.read",       "(?i)ReadAllText"),
          ("CWE-22",  "fs.read",       "(?i)ReadAllBytes"),
          ("CWE-22",  "fs.read",       "(?i)OpenRead"),
          ("CWE-22",  "fs.read",       "(?i)Open"),
          ("CWE-502", "deser.unsafe",  "(?i)Deserialize"),
          ("CWE-502", "deser.unsafe",  "(?i)DeserializeObject"),
          ("CWE-502", "deser.unsafe",  "(?i)ReadObject"),
          // Open redirect — MVC ``Redirect`` / ``RedirectToAction`` / ``RedirectToRoute``.
          ("CWE-601", "open.redirect", "(?i)^Redirect$"),
          ("CWE-601", "open.redirect", "(?i)^RedirectToAction$"),
          ("CWE-601", "open.redirect", "(?i)^RedirectToRoute$"),
          // Phase 20 — XXE. ``XmlDocument.LoadXml`` resolves entities on
          // .NET Framework by default (``XmlResolver`` non-null); modern
          // .NET Core defaults are safe, so the reviewer confirms the TFM.
          ("CWE-611", "xml.parse",     "(?i)^(LoadXml|XmlTextReader|XPathDocument)$"),
          // Phase 20 — response splitting via header write.
          ("CWE-93",  "header.write",  "(?i)^(AppendHeader|AddHeader)$"),
          // Phase 21 — logging / LDAP / XPath / ReDoS.
          ("CWE-532", "log.sensitive", "(?i)^(LogTrace|LogDebug|LogInformation|LogWarning|LogError|LogCritical)$"),
          ("CWE-90",  "ldap.query",    "(?i)^(FindOne|FindAll)$"),
          ("CWE-643", "xpath.query",   "(?i)^(Select|Evaluate|Compile|SelectNodes|SelectSingleNode)$"),
          ("CWE-1333", "redos",        "(?i)^(<init>|IsMatch)$")
        )
      )
    case "php" =>
      LangPatterns(
        sourcePattern =
          "(?i)(\\$_GET|\\$_POST|\\$_REQUEST|\\$_COOKIE|\\$_SERVER|\\$_FILES|" +
          "\\$_ENV|getenv|php://input).*",
        sinkClasses = List(
          ("CWE-89",  "sql.exec",      "(?i)query"),
          ("CWE-89",  "sql.exec",      "(?i)exec"),
          ("CWE-89",  "sql.exec",      "(?i)mysqli_query"),
          ("CWE-89",  "sql.exec",      "(?i)multi_query"),
          ("CWE-89",  "sql.exec",      "(?i)get_results"),
          ("CWE-89",  "sql.exec",      "(?i)get_var"),
          ("CWE-89",  "sql.exec",      "(?i)get_row"),
          ("CWE-78",  "cmd.shell",     "(?i)shell_exec"),
          ("CWE-78",  "cmd.shell",     "(?i)passthru"),
          ("CWE-78",  "cmd.shell",     "(?i)system"),
          ("CWE-78",  "cmd.shell",     "(?i)proc_open"),
          ("CWE-78",  "cmd.shell",     "(?i)popen"),
          ("CWE-79",  "html.write",    "(?i)echo"),
          ("CWE-79",  "html.write",    "(?i)print"),
          ("CWE-22",  "fs.read",       "(?i)file_get_contents"),
          ("CWE-22",  "fs.read",       "(?i)fopen"),
          ("CWE-22",  "fs.read",       "(?i)readfile"),
          ("CWE-22",  "fs.read",       "(?i)include"),
          ("CWE-22",  "fs.read",       "(?i)require"),
          ("CWE-502", "deser.unsafe",  "(?i)unserialize"),
          ("CWE-94",  "code.exec",     "(?i)eval"),
          ("CWE-94",  "code.exec",     "(?i)assert"),
          ("CWE-94",  "code.exec",     "(?i)create_function"),
          ("CWE-918", "ssrf",          "(?i)curl_exec"),
          // Phase 20 — XXE. libxml2 < 2.9 resolved entities by default and
          // ``LIBXML_NOENT`` re-enables it explicitly; both remain common.
          ("CWE-611", "xml.parse",     "(?i)^(simplexml_load_string|simplexml_load_file|loadXML|loadHTML)$"),
          // Phase 20 — response splitting: PHP ``header()`` writes a raw
          // header line. PHP has rejected CRLF in header() since 5.1.2, so
          // the practical impact is usually limited — still flagged.
          ("CWE-93",  "header.write",  "(?i)^header$"),
          // Phase 21 — email header injection. PHP's ``mail()`` takes the
          // additional-headers parameter verbatim; CRLF there injects Bcc.
          ("CWE-93",  "email.send",    "(?i)^mail$"),
          // Phase 21 — LDAP + XPath injection.
          ("CWE-90",  "ldap.query",    "(?i)^(ldap_search|ldap_list|ldap_read)$"),
          ("CWE-643", "xpath.query",   "(?i)^(xpath|query|evaluate)$")
        )
      )
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
          // Rails ``send_data(html_body, type: 'text/html')`` and
          // ``render inline: html_body``. Names are specific enough; the
          // user's content-type / inline flag is the security-critical
          // detail and is reviewer-confirmed.
          ("CWE-79",  "html.write",    "(?i)^send_data$"),
          ("CWE-22",  "fs.read",       "(?i)read"),
          ("CWE-22",  "fs.read",       "(?i)open"),
          ("CWE-22",  "fs.read",       "(?i)binread"),
          ("CWE-502", "deser.unsafe",  "(?i)load"),
          ("CWE-502", "deser.unsafe",  "(?i)restore"),
          ("CWE-94",  "code.exec",     "(?i)eval"),
          ("CWE-94",  "code.exec",     "(?i)instance_eval"),
          ("CWE-94",  "code.exec",     "(?i)class_eval"),
          // Open redirect — Rails ``redirect_to`` with a user-controlled URL.
          ("CWE-601", "open.redirect", "(?i)^redirect_to$"),
          // Phase 20 — XXE. Nokogiri is safe by default; ``noent`` opts back
          // in. REXML historically resolved entities (also a billion-laughs
          // DoS surface).
          ("CWE-611", "xml.parse",     "(?i)^(XML|parse|noent)$"),
          // Phase 20 — response splitting via a raw header assignment.
          ("CWE-93",  "header.write",  "(?i)^(set_header|headers)$"),
          // Phase 21 — SSTI. rubysrc2cpg lowers ``ERB.new(user)`` to the
          // receiver-specific ``erb.ERB.initialize`` call.
          ("CWE-1336", "ssti",         "(?i)^initialize$"),
          // Phase 21 — email header injection (ActionMailer / the mail gem).
          ("CWE-93",  "email.send",    "(?i)^(deliver|deliver_now|deliver_later)$"),
          // Phase 21 — sensitive data in logs.
          ("CWE-532", "log.sensitive", "(?i)^(debug|info|warn|error|fatal)$")
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
          ("CWE-502", "deser.unsafe",  "(?i)Unmarshal"),
          // Phase 6: Go SSRF sinks. `net/http`'s top-level shortcuts and
          // `client.Do(req)` after `http.NewRequest`. Pattern style
          // matches the other Go sinks (unanchored substring). `Get` is
          // intentionally NOT included — bare `Get` over-matches map.Get,
          // atomic loads, etc. We rely on `Do`, `Post`, `Head`, and the
          // explicit `NewRequest*` constructors. For `http.Get(url)`
          // specifically, `Get` after a known HTTP-client receiver would
          // need a receiver filter (deferred to Phase 5 extensions).
          ("CWE-918", "ssrf",          "(?i)(Post|PostForm|NewRequest|NewRequestWithContext)"),
          ("CWE-918", "ssrf",          "(?i)\\bDo$"),
          // Open redirect — ``http.Redirect(w, r, url, code)`` from net/http.
          // The bare ``^Redirect$`` is specific enough for Go's HTTP idioms.
          ("CWE-601", "open.redirect", "(?i)^Redirect$"),
          // Phase 20 — response splitting. ``w.Header().Set(k, v)`` /
          // ``.Add(k, v)`` write raw header values. Go's net/http sanitises
          // CRLF on write, so this is mostly a proxy-layer concern — flagged
          // for reviewer judgement rather than treated as certain.
          ("CWE-93",  "header.write",  "(?i)^(Set|Add)$"),
          // Phase 21 — email header injection via net/smtp.
          ("CWE-93",  "email.send",    "(?i)^SendMail$"),
          // Phase 21 — SSTI. Only Parse consumes template source. ParseGlob /
          // ParseFiles consume filenames, and Must merely unwraps a result.
          ("CWE-1336", "ssti",         "(?i)^Parse$")
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
          ("CWE-502", "deser.unsafe",  "(?i)deserialize"),
          // Phase 6: Java SSRF sinks. RestTemplate / WebClient / Apache
          // HttpClient / URL.openStream are the dominant HTTP-client
          // shapes in Spring code. Pattern style matches the existing
          // Java sinks (case-insensitive substring, NOT anchored — Joern's
          // ``cpg.call.name(regex)`` treats the regex as a full match per
          // line, but the existing ``queryForObject`` etc. style works
          // unanchored). ``getForObject``/``postForObject`` etc. are
          // RestTemplate-specific; ``exchange`` is the generic API;
          // ``openConnection``/``openStream`` covers stdlib URL paths.
          // ``put``/``delete`` deliberately excluded — too generic outside
          // HTTP-client context.
          ("CWE-918", "ssrf",          "(?i)(getForObject|getForEntity|postForObject|postForEntity|patchForObject|patchForEntity|exchange)"),
          ("CWE-918", "ssrf",          "(?i)(openConnection|openStream)"),
          // Open redirect — Servlet ``HttpServletResponse.sendRedirect`` is
          // the canonical Java sink.
          ("CWE-601", "open.redirect", "(?i)^sendRedirect$"),
          // Phase 20 — XXE. The Java XML stack is unsafe by DEFAULT: a
          // ``DocumentBuilderFactory`` / ``SAXParserFactory`` that has not had
          // ``setFeature(disallow-doctype-decl, true)`` applied will resolve
          // external entities. We flag the parse call and let the mitigations
          // layer / reviewer confirm whether hardening was applied.
          ("CWE-611", "xml.parse",     "(?i)^(parse|unmarshal|read)$"),
          ("CWE-611", "xml.parse",     "(?i)^(newDocumentBuilder|newSAXParser|createXMLStreamReader)$"),
          // Phase 20 — HTTP response splitting. CRLF in an attacker-controlled
          // header value splits the response. ``addCookie`` is included
          // because the cookie value lands in a Set-Cookie header.
          ("CWE-93",  "header.write",  "(?i)^(setHeader|addHeader|addCookie)$"),
          // Phase 21 — sensitive data in logs (SLF4J / Log4j / java.util.logging).
          ("CWE-532", "log.sensitive", "(?i)^(trace|debug|info|warn|error|fatal|severe)$"),
          // Phase 21 — SSTI. Velocity.evaluate consumes template source in
          // argument four; FreeMarker consumes it in Template's constructor.
          // ``Template.process`` only receives the data model and is not a
          // template-injection sink.
          ("CWE-1336", "ssti",         "(?i)^(evaluate|<init>)$"),
          // Phase 21 — XPath injection (javax.xml.xpath).
          ("CWE-643", "xpath.query",   "(?i)^(evaluate|compile|evaluateExpression|compileExpression|selectNodes|selectSingleNode)$"),
          // Phase 21 — LDAP injection. ``DirContext.search`` with a filter
          // built from user input subverts the filter logic.
          ("CWE-90",  "ldap.query",    "(?i)^(search|searchControls)$")
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
          // Reflected XSS via Flask ``make_response`` and Django ``HttpResponse``
          // when the body is concatenated from request input. Both are
          // specific enough names to skip a receiver filter.
          ("CWE-79",  "html.write",    "(?i)^(make_response|HttpResponse)$"),
          // SSTI — server-side template injection. ``render_template_string``
          // is also CWE-1336 when the *template* itself is user-controlled
          // (not just rendered output). The same flow records both CWE rows;
          // reviewers + scoring disambiguate.
          ("CWE-1336", "ssti",         "(?i)render_template_string"),
          ("CWE-22",  "fs.read",       "(?i)open"),
          // SSRF: ``urlopen`` is bare-specific; the HTTP-client bare methods
          // (``get``/``post``/etc.) are filtered by ``pythonSsrfReceiver``
          // below to require a known client receiver (requests/httpx/urllib3/
          // aiohttp). Closes the python-flask-ssrf gap from the 2026-05-15
          // eval baseline (Invariant 5 — every model expansion ships with a
          // negative target: eval-targets/python-flask-ssrf-allowlist).
          ("CWE-918", "ssrf",          "(?i)^(urlopen)$"),
          ("CWE-918", "ssrf",          "(?i)^(get|post|put|delete|patch|head|options|request)$"),
          ("CWE-502", "deser.unsafe",  "(?i)loads"),
          ("CWE-502", "deser.unsafe",  "(?i)(load|full_load|unsafe_load)"),
          // Open redirect — Flask ``redirect``, FastAPI ``RedirectResponse``,
          // Django ``HttpResponseRedirect``. All three are specific names.
          ("CWE-601", "open.redirect", "(?i)^(redirect|RedirectResponse|HttpResponseRedirect)$"),
          // Email / SMTP header injection — ``smtplib.SMTP.send_message`` and
          // ``send_mail`` (Django) are the dominant Python mail sinks.
          ("CWE-93",  "email.send",    "(?i)^(send_message|send_mail|sendmail)$"),
          // Phase 20 — XXE. ``lxml.etree`` resolves external entities unless
          // an explicit hardened ``XMLParser(resolve_entities=False)`` is
          // passed; stdlib ``xml.sax`` / ``xml.dom.minidom`` are likewise
          // unsafe pre-3.7.1 defaults. ``fromstring``/``parse`` are the two
          // entry shapes. Note ``parse`` also matches other libraries — the
          // reviewer confirms the receiver is an XML parser.
          ("CWE-611", "xml.parse",     "(?i)^(fromstring|parseString|parse)$"),
          ("CWE-611", "xml.parse",     "(?i)^(XMLParser|XMLPullParser)$"),
          // Phase 21 — sensitive data in logs. Mirrors the JS log.sensitive
          // sink set; the *source* side (auth headers, tokens, passwords) is
          // what makes a hit interesting, so the bare logger method names are
          // acceptable here.
          ("CWE-532", "log.sensitive", "(?i)^(debug|info|warning|warn|error|critical|exception)$"),
          // Phase 21/22 — NoSQL operator injection (pymongo / motor). Bare
          // ``find`` is receiver-gated below so ``str.find`` remains excluded.
          ("CWE-943", "nosql.query",   "(?i)^(find|find_one|find_one_and_update|find_one_and_delete|aggregate|map_reduce|distinct)$"),
          // Phase 21 — LDAP injection (python-ldap / ldap3). Filter strings
          // built from user input allow filter-logic subversion.
          ("CWE-90",  "ldap.query",    "(?i)^(search_s|search_ext_s|search_st)$"),
          // Phase 21 — XPath injection (lxml / ElementTree).
          ("CWE-643", "xpath.query",   "(?i)^(xpath|iterfind)$"),
          // Phase 21 — ReDoS via an attacker-supplied pattern. ONLY
          // ``re.compile`` is modelled: its arguments are (pattern, flags),
          // so a tainted argument really is the pattern. ``re.search`` /
          // ``sub`` / ``findall`` take (pattern, STRING) and the string is
          // attacker-controlled in almost every correct program — modelling
          // them would fire on nearly every Python file that greps user input
          // and would bury the real hits.
          ("CWE-1333", "redos",        "(?i)^compile$")
        )
      )
    case "javascript" | "typescript" | "jssrc" | _ =>
      val ce = "exec"
      val cs = "spawn"
      LangPatterns(
        // Sources are the union of:
        //   - server-side request shapes (Express/Koa/Fastify ``req.*``,
        //     Firebase Callable ``request.data``/``request.auth``,
        //     CLI ``process.argv``); the ``\\.body`` etc. tail-matches help
        //     when Joern's JS frontend lowers ``req.body`` through a temp
        //     variable (``_tmp_N.body``);
        //   - DOM-XSS sources for pure-JS frontends: ``location.hash`` /
        //     ``.search`` / ``.href`` / ``.pathname``, ``document.URL`` /
        //     ``.referrer`` / ``.baseURI`` / ``.documentURI``,
        //     ``window.name``, ``event.data`` (MessageEvent), ``history.state``,
        //     ``localStorage.getItem`` / ``sessionStorage.getItem``,
        //     ``URLSearchParams``.
        sourcePattern = "(?i)(" +
          "req\\.body|req\\.query|req\\.params|req\\.headers|req\\.cookies|" +
          "req\\.rawBody|req\\.url|" +
          "request\\.data|request\\.body|request\\.query|request\\.params|" +
          "request\\.headers|request\\.auth|" +
          "process\\.argv|" +
          "location\\.hash|location\\.search|location\\.href|location\\.pathname|" +
          "document\\.URL|document\\.referrer|document\\.baseURI|document\\.documentURI|" +
          "window\\.name|event\\.data|history\\.state|" +
          "localStorage\\.getItem|sessionStorage\\.getItem|URLSearchParams" +
          ").*",
        sinkClasses = List(
          ("CWE-89", "sql.exec",     "(?i)query"),
          ("CWE-89", "sql.exec",     "(?i)execute"),
          ("CWE-78", "cmd.shell",    s"(?i)${ce}(Sync)?"),
          ("CWE-78", "cmd.shell",    s"(?i)${cs}(Sync)?"),
          // Server-side response writes (``res.send/write/end``) plus the
          // DOM ``document.write/writeln`` shape — both share the ambiguous
          // ``send``/``write``/``end``/``writeln`` call names. The
          // ``xssReceiver`` regex disambiguates them by receiver text.
          ("CWE-79", "html.write",   "(?i)^(send|write|end|writeln)$"),
          // DOM-XSS specific sinks. Names are precise enough that
          // ``restrictXssSinks`` lets them through without a receiver filter.
          ("CWE-79", "html.write",   "(?i)^insertAdjacentHTML$"),
          ("CWE-79", "html.write",   "(?i)^parseHTML$"),
          // Code execution via dynamic evaluation. ``eval``/``Function`` are
          // unambiguous; ``setTimeout``/``setInterval`` only matter when the
          // first argument is a string (we still flag the call — reviewers
          // confirm).
          ("CWE-94", "code.exec",    "(?i)^eval$"),
          ("CWE-94", "code.exec",    "(?i)^Function$"),
          ("CWE-94", "code.exec",    "(?i)^setTimeout$"),
          ("CWE-94", "code.exec",    "(?i)^setInterval$"),
          ("CWE-22", "fs.read",      "(?i)(readFile|createReadStream|readFileSync)"),
          // SSRF: bare ``fetch(...)`` and ``request(...)`` (legacy npm) match
          // by themselves. ``get``/``post``/``put``/``delete``/``patch`` etc.
          // match too, but the ``ssrfReceiver`` regex below filters those down
          // to receivers like ``axios.``/``http.``/``https.``/``client.``/``got.``
          // so we don't flag ``Array.get`` or ``Map.get`` (Recall-First
          // Invariant 5: model expansion lands with negative eval targets —
          // see eval-targets/express-ssrf-allowlist).
          ("CWE-918", "ssrf",        "(?i)^(fetch|request|get|post|put|delete|patch|head|options)$"),
          ("CWE-532", "log.sensitive", "(?i)^(log|error|warn|info|debug|trace|fatal)$"),
          // Firestore document operations. ``doc(<id>)`` with attacker-
          // controlled id is the IDOR shape; ``set``/``update`` with
          // attacker-controlled bodies enable mass-assignment style
          // privilege escalation when rules don't restrict fields.
          ("CWE-639", "firestore.idor",   "(?i)^doc$"),
          ("CWE-915", "firestore.write",  "(?i)^(set|update|create)$"),
          ("CWE-943", "firestore.query",  "(?i)^(where|orderBy)$"),
          // Open redirect — Express ``res.redirect(url)``, Koa ``ctx.redirect(url)``.
          // ``location.assign`` / ``location.replace`` are *not* matched here
          // because the bare names ``assign``/``replace`` over-match Object.assign,
          // String.replace, etc. The DOM open-redirect assignment shape
          // (``location.href = userInput``) is a candidate for Phase 16's
          // property-assignment scan — deferred.
          ("CWE-601", "open.redirect",  "(?i)^redirect$"),
          // Email / SMTP header injection — nodemailer's ``sendMail`` is the
          // dominant Node mailer; ``sendgrid.send`` and ``ses.sendEmail`` are
          // common SaaS variants. CRLF in attacker-controlled to/subject
          // fields lets them inject Bcc, alter envelopes, or splice the body.
          ("CWE-93",  "email.send",    "(?i)^sendMail$"),
          ("CWE-93",  "email.send",    "(?i)^sendEmail$"),
          // Phase 20 — HTTP response splitting / header injection. Express
          // ``res.setHeader`` / ``res.header`` / ``res.append`` all write a
          // raw header value. Node core rejects CRLF in header values since
          // v8, so the modern impact is usually header *injection* into
          // proxies rather than full response splitting — still worth a flag.
          ("CWE-93",  "header.write",  "(?i)^(setHeader|append)$"),
          // Phase 20 — prototype pollution. Deep-merge / deep-set helpers
          // copy attacker keys (``__proto__`` / ``constructor.prototype``)
          // onto Object.prototype when handed an unsanitised request body.
          // ``merge`` / ``extend`` / ``set`` are lodash + jQuery + the
          // ``deepmerge`` npm package; the receiver is unconstrained on
          // purpose (a hand-rolled ``merge(target, req.body)`` is the most
          // common real-world shape).
          // ``set``/``setWith`` are filtered by ``protoPolluteReceiver`` below
          // so we don't collide with the Firestore ``doc().set()`` sink.
          ("CWE-1321", "proto.pollute", "(?i)^(merge|mergeWith|defaultsDeep|extend|deepmerge)$"),
          ("CWE-1321", "proto.pollute", "(?i)^(set|setWith)$"),
          // Phase 21/22 — NoSQL (operator) injection. Passing ``req.body``
          // straight to a Mongo query lets the attacker supply operators
          // (for example ``{"$ne": null}``) instead of a scalar value.
          // Canonical bare ``find`` is receiver-gated below so
          // Array.prototype.find does not masquerade as a database query.
          ("CWE-943", "nosql.query",   "(?i)^(find|findOne|findOneAndUpdate|findOneAndDelete|findOneAndReplace)$"),
          ("CWE-943", "nosql.query",   "(?i)^(updateMany|deleteMany|countDocuments|aggregate|mapReduce|distinct)$"),
          // Phase 21 — client/server SSTI. Handlebars ``compile`` and lodash
          // ``template`` interpret their argument as a template; an
          // attacker-controlled template string is RCE (server) or XSS
          // (browser).
          ("CWE-1336", "ssti",         "(?i)^(compile|template)$"),
          // Phase 21 — ReDoS. ``new RegExp(userInput)`` lets the attacker
          // pick a catastrophically backtracking pattern.
          ("CWE-1333", "redos",        "(?i)^(RegExp|<operator>\\.new)$")
        )
      )
  }
  val sourceNamePattern = patterns.sourcePattern

  // Phase 5: merge optional extension sinks from a JSON config. Path is
  // passed via the AICS_JOERN_EXTENSIONS env var (set by the Python plumbing
  // when the repo has a non-empty aics-joern-extension-packs.json). The
  // schema is owned by ai_codescan/joern_extensions.py. A missing or
  // malformed file is silently ignored — Joern scans must not fail on a
  // corrupted config (recall-first does not mean "fail-open on tooling").
  val extensionPath = sys.env.getOrElse("AICS_JOERN_EXTENSIONS", "")
  val (extensionSinks, extensionReceiverMap): (
    List[(String, String, String)],
    Map[(String, String, String), String]
  ) = {
    if (extensionPath.isEmpty) {
      (List.empty, Map.empty)
    } else {
      val f = new java.io.File(extensionPath)
      if (!f.isFile()) {
        (List.empty, Map.empty)
      } else {
        try {
          val raw = java.nio.file.Files.readString(f.toPath())
          val payload = ujson.read(raw)
          val rawSinks = payload.obj.getOrElse("sinks", ujson.Arr()).arr.toList
          val sinks = rawSinks.flatMap { item =>
            val itemLang =
              item.obj.getOrElse("language", ujson.Str("")).str.toLowerCase
            if (itemLang == language.toLowerCase) {
              val cwe = item.obj.getOrElse("cwe", ujson.Str("")).str
              val sinkClass =
                item.obj.getOrElse("sink_class", ujson.Str("unknown")).str
              val pattern = item.obj.getOrElse("pattern", ujson.Str("")).str
              if (pattern.nonEmpty) Some((cwe, sinkClass, pattern)) else None
            } else None
          }
          val recvMap = rawSinks.flatMap { item =>
            val itemLang =
              item.obj.getOrElse("language", ujson.Str("")).str.toLowerCase
            if (itemLang == language.toLowerCase) {
              val recv =
                item.obj.getOrElse("receiver_regex", ujson.Str("")).str
              if (recv.nonEmpty) {
                val cwe = item.obj.getOrElse("cwe", ujson.Str("")).str
                val sinkClass =
                  item.obj.getOrElse("sink_class", ujson.Str("unknown")).str
                val pattern =
                  item.obj.getOrElse("pattern", ujson.Str("")).str
                Some(((cwe, sinkClass, pattern), recv))
              } else None
            } else None
          }.toMap
          (sinks, recvMap)
        } catch {
          case _: Throwable => (List.empty, Map.empty)
        }
      }
    }
  }
  val sinkClasses = patterns.sinkClasses ++ extensionSinks

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
  // JVM request-borne data flows through method parameters that carry
  // annotations like @RequestParam / @RequestBody / @PathVariable rather
  // than top-level field reads, so for Java we additionally include matching
  // parameter nodes. Java usually includes the annotation in ``code``;
  // Kotlin exposes it through the parameter's annotation edge instead.
  val baseRawSources = cpg.fieldAccess.code(sourceNamePattern).l ++
                       cpg.identifier.name(sourceNamePattern).l
  val srcRegex = sourceNamePattern.r
  val rawSources =
    if (language.toLowerCase == "java" || language.toLowerCase == "kotlin") {
      val jvmParamSources =
        cpg.parameter
          .filter { p =>
            val codeMatches = p.code != null && srcRegex.findFirstIn(p.code).isDefined
            val annotationMatches = p.annotation.name.l.exists { name =>
              srcRegex.findFirstIn(name).isDefined
            }
            codeMatches || annotationMatches
          }
          .l
      baseRawSources ++ jvmParamSources
    } else if (language.toLowerCase == "go" || language.toLowerCase == "golang") {
      // Go's request data lands via method calls on the request/context
      // object (``c.Query("id")``, ``r.URL.Query()``); the *call result* is
      // the taint source, so include matching call nodes alongside
      // identifier/fieldAccess reads.
      val goCallSources = cpg.call.code(sourceNamePattern).l
      baseRawSources ++ goCallSources
    } else if (language.toLowerCase == "python") {
      // Indexed Flask/Django reads such as request.args["pattern"] are
      // operator calls in pythonsrc2cpg. Include that expression so taint is
      // not lost at the fieldAccess -> indexAccess boundary.
      val pythonCallSources = cpg.call.code(sourceNamePattern).l
      baseRawSources ++ pythonCallSources
    } else if (language.toLowerCase == "csharp" || language.toLowerCase == "csharpsrc") {
      // ASP.NET Core minimal APIs bind simple lambda parameters from the
      // request by convention. Joern's C# frontend exposes those as parameter
      // nodes (e.g. ``id:System.String``), not as Request.Query field reads.
      val csharpParamSources =
        cpg.parameter
          .filter(p => p.lineNumber.nonEmpty && p.name != "args" && p.name != "this")
          .l
      baseRawSources ++ csharpParamSources
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
  // Disambiguator for the ambiguous JS XSS call names ``send``/``write``/``end``/
  // ``writeln``. Accepts server-side response writers (``res.send`` / ``response.write`` /
  // ``reply.end`` / ``ctx.write``) AND the DOM ``document.write`` / ``document.writeln``
  // shape. Other DOM-XSS sink names (``insertAdjacentHTML`` / ``parseHTML`` / ``eval``
  // / ``setTimeout`` / ``setInterval``) are specific enough that they pass through
  // ``restrictXssSinks`` without a receiver filter.
  val xssReceiver =
    """(?is).*\b(?:(?:res|response|reply|ctx)\.(?:send|write|end)|document\.(?:write|writeln))\b.*""".r
  // Call names that ``restrictXssSinks`` filters via ``xssReceiver`` — the
  // ambiguous server-vs-DOM set. Everything else in the JS CWE-79 family passes
  // through unfiltered (the names are precise: ``insertAdjacentHTML`` / ``parseHTML``).
  val xssAmbiguousCallNames = Set("send", "write", "end", "writeln")
  // SSRF receiver allowlist: when the call name is ``get``/``post``/`put`` etc.
  // (which over-match outside HTTP clients), require the receiver text to look
  // like a known HTTP client (axios/http/https/client/got). Bare ``fetch`` and
  // bare ``request`` calls aren't filtered (they're specific enough on their own).
  val ssrfReceiver =
    """(?is).*\b(?:axios|http|https|client|got|node-fetch|undici|needle|superagent)\.(?:get|post|put|delete|patch|head|options|request)\b.*""".r
  val ssrfBareNames = Set("fetch", "request")
  // Phase 20: prototype-pollution receiver gate. ``set``/``setWith`` are
  // ambiguous — Firestore's ``doc(id).set(body)`` is a mass-assignment sink
  // (CWE-915), not prototype pollution. Requiring a lodash/underscore-shaped
  // receiver keeps the CWE-1321 class honest. The deep-merge names
  // (``merge``/``defaultsDeep``/``deepmerge``/...) are specific enough that
  // they are NOT filtered — a hand-rolled ``merge(target, req.body)`` is the
  // most common real-world prototype-pollution shape and has no receiver.
  val protoPolluteAmbiguousNames = Set("set", "setwith")
  val protoPolluteReceiver =
    """(?is).*\b(?:_|lodash|underscore|objectPath|dotProp|dot-prop)\.\s*set(?:With)?\b.*""".r
  // Phase 21: Firestore receiver gate. ``set``/``update``/``create`` are far
  // too generic on their own — Phase 20 verification caught
  // ``Object.create(null)`` being reported as a Firestore mass-assignment
  // sink. Require a Firestore-shaped receiver: a ``doc(...)``/``collection(...)``
  // chain, or a Firestore/document-reference identifier. A generic ``db``
  // receiver is intentionally insufficient because SQL/Redis clients use it.
  val firestoreReceiver =
    ("""(?is).*(?:\.doc\s*\(|\.collection\s*\(|\bfirestore\b|""" +
      """\bdocRef\b|\bcollectionRef\b).*""").r
  // Phase 22: receiver/type gates for names that are security sinks only on
  // particular APIs. methodFullName is preferred; source-code receiver text
  // is the fallback for frontends with incomplete type recovery.
  val jsSstiReceiver =
    """(?is).*(?:handlebars|lodash|nunjucks|pug|ejs|dot)(?::|\.).*(?:compile|template).*""".r
  val jsRegExpConstructor = """(?is).*\b(?:new\s+)?RegExp\s*\(.*""".r
  val jsMongoReceiver =
    """(?is).*(?:mongodb|mongoose|mongojs|monk|\b(?:mongo|collection|coll)\w*\.).*""".r
  val javaSstiReceiver =
    """(?is).*(?:org\.apache\.velocity.*\.evaluate|freemarker\.template\.Template\.<init>).*""".r
  val jvmXpathReceiver =
    """(?is).*(?:javax\.xml\.xpath|org\.apache\.xpath|\bXPath\w*(?:\.|\b)|\bxpath\.).*""".r
  val jvmLdapReceiver =
    """(?is).*(?:javax\.naming|ldap|DirContext|LdapContext|\b(?:directory|ldap)\w*\.).*""".r
  val csharpRegexReceiver = """(?is).*(?:\bRegex\.|\bRegex\.<init>|new\s+Regex\s*\().*""".r
  val csharpXpathReceiver =
    """(?is).*(?:XPath|XmlDocument|XmlNode|XmlElement|\b(?:xpath|navigator)\w*\.).*""".r
  val pythonRegexReceiver = """(?is).*(?:\bre(?:gex)?(?:\.py)?[:.]|\bre(?:gex)?\.compile).*""".r
  val pythonMongoReceiver =
    """(?is).*(?:pymongo|motor|mongoengine|beanie|\b(?:mongo|collection|coll)\w*\.).*""".r
  val phpXpathReceiver =
    ("""(?is).*(?:DOMXPath|SimpleXMLElement|""" +
      """\b\w*xpath\w*\s*->\s*(?:query|evaluate)\s*\().*""").r
  val rubyErbReceiver = """(?is).*(?:erb\.ERB\.initialize|ERB\.new\s*\().*""".r
  val goTemplateReceiver = """(?is).*(?:html/template|text/template)[^\s]*\.Parse\s.*""".r
  // Python SSRF: bare ``urlopen`` is specific enough on its own; the bare
  // method names (get/post/etc.) need receiver filtering to avoid matching
  // e.g. ``dict.get`` / ``Session.get`` outside HTTP-client contexts. The
  // regex also accepts a small allowlist of HTTP-client-strong variable
  // names so aliased clients like
  //   http_client = httpx.Client(); http_client.get(url)
  // are caught. Generic names (``client``/``session``/``http``/``api``) are
  // deliberately NOT in the allowlist — too broad; would over-match Redis
  // clients, Flask `session`, etc. For arbitrary alias names we fall back
  // to the ``pythonHttpClientVars`` set built below by walking constructor
  // assignments — that's the type-aware path the user asked for.
  val pythonSsrfReceiver =
    ("""(?is).*\b(?:requests|httpx|urllib3|urllib\.request|aiohttp|Session\(\)|session|""" +
      """http_client|httpx_client|api_client|requests_session|""" +
      """http_session)\.(?:get|post|put|delete|patch|head|options|request)\b.*""").r
  val pythonSsrfBareNames = Set("urlopen")

  type CallNode = io.shiftleft.codepropertygraph.generated.nodes.Call

  def receiverCode(call: CallNode): String =
    call.argument.l
      .find(_.argumentIndex == 0)
      .map(node => if (node.code != null) node.code else "")
      .getOrElse("")

  def callDescriptor(call: CallNode): String = {
    val code = if (call.code != null) call.code else ""
    val fullName = if (call.methodFullName != null) call.methodFullName else ""
    s"$fullName $code ${receiverCode(call)}"
  }

  def assignedReceiverVars(
    enabled: Boolean,
    seedPattern: scala.util.matching.Regex
  ): scala.collection.mutable.HashSet[String] = {
    val found = scala.collection.mutable.HashSet.empty[String]
    if (!enabled) return found
    val assignments = cpg.call.name("<operator>.assignment").l
    assignments.foreach { assignment =>
      val args = assignment.argument.l
      if (args.length >= 2) {
        val lhsCode = if (args.head.code != null) args.head.code else ""
        val rhsCode = if (args(1).code != null) args(1).code else ""
        val lhsName = lhsCode.trim.takeWhile(char => char.isLetterOrDigit || char == '_')
        if (lhsName.nonEmpty && seedPattern.findFirstIn(rhsCode).isDefined) {
          found.add(lhsName)
        }
      }
    }
    var grew = true
    while (grew) {
      grew = false
      assignments.foreach { assignment =>
        val args = assignment.argument.l
        if (args.length >= 2) {
          val lhsCode = if (args.head.code != null) args.head.code else ""
          val rhsCode = if (args(1).code != null) args(1).code else ""
          val lhsName = lhsCode.trim.takeWhile(char => char.isLetterOrDigit || char == '_')
          val rhsName = rhsCode.trim
          if (
            lhsName.nonEmpty && rhsName.matches("[A-Za-z_]\\w*") &&
            found.contains(rhsName) && !found.contains(lhsName)
          ) {
            found.add(lhsName)
            grew = true
          }
        }
      }
    }
    found
  }

  val jsMongoCollectionVars = assignedReceiverVars(
    language.toLowerCase.matches("javascript|typescript|jssrc"),
    """(?is).*(?:\.collection\s*\(|mongoose\.model\s*\(|mongojs\s*\().*""".r
  )

  // Type-aware Python HTTP-client receiver discovery.
  //
  // Two complementary collection passes feed `pythonHttpClientVars`:
  //
  // 1. **typeFullName pre-pass.** When scip-python has populated rich type
  //    information into the Joern CPG, every identifier (or fieldAccess)
  //    assigned an HTTP-client instance carries a typeFullName that
  //    contains the class. We collect those names directly. This is the
  //    only path that catches *transitive* aliasing:
  //        client = httpx.Client()
  //        api    = client
  //        api.get(url)        # api.typeFullName ~ httpx.Client
  //
  // 2. **Assignment AST pre-pass.** As a fallback for partial type
  //    coverage (or non-scip-python builds), we walk every
  //    `<operator>.assignment` call and look at argument(2) (the RHS).
  //    When it's a Call whose code matches an HTTP-client constructor,
  //    we record argument(1).code (the LHS identifier name).
  //
  // The union is consulted in the SSRF receiver filter below.
  val pythonHttpClientVars = scala.collection.mutable.HashSet.empty[String]
  val pythonHttpClientTypeNeedle =
    """(?i).*\b(?:httpx\.Client|requests\.Session|aiohttp\.ClientSession)\b.*""".r
  val pythonHttpClientRhsRegex =
    """(?i)\b(?:httpx\.Client|requests\.Session|aiohttp\.ClientSession)\s*\(""".r

  if (language.toLowerCase == "python") {
    // Pass 1: typeFullName scan. Every identifier whose declared type is an
    // HTTP-client class is a valid receiver — covers transitive aliasing.
    cpg.identifier.foreach { id =>
      val tName = if (id.typeFullName != null) id.typeFullName else ""
      if (pythonHttpClientTypeNeedle.matches(tName)) {
        val name = if (id.name != null) id.name else ""
        if (name.nonEmpty) pythonHttpClientVars.add(name)
      }
    }

    // Pass 2: assignment AST walk. CPG navigation, not regex-on-full-text.
    // We use argument(1).code and argument(2).code so PEP 526 annotations
    // and unusual whitespace formatting don't matter; the parser already
    // split the assignment into its constituent expressions.
    cpg.call.name("<operator>.assignment").foreach { a =>
      val args = a.argument.l
      if (args.length >= 2) {
        val lhsCode = if (args.head.code != null) args.head.code else ""
        val rhsCode = if (args(1).code != null) args(1).code else ""
        // LHS may be a bare identifier (``client``) or an annotated
        // identifier (``client: httpx.Client`` in PEP 526). Strip a
        // trailing type annotation to recover the bare name.
        val lhsName = lhsCode.trim.takeWhile(c => c.isLetterOrDigit || c == '_')
        if (
          lhsName.nonEmpty &&
          pythonHttpClientRhsRegex.findFirstIn(rhsCode).isDefined
        ) {
          pythonHttpClientVars.add(lhsName)
        }
      }
    }

    // Pass 3: transitive aliasing via assignment AST. When the RHS is an
    // identifier already in pythonHttpClientVars (alias chain), the LHS
    // joins the set. Iterate until fixed point so chains of arbitrary
    // length resolve.
    var grew = true
    while (grew) {
      grew = false
      cpg.call.name("<operator>.assignment").foreach { a =>
        val args = a.argument.l
        if (args.length >= 2) {
          val lhsCode = if (args.head.code != null) args.head.code else ""
          val rhsCode = if (args(1).code != null) args(1).code else ""
          val lhsName = lhsCode.trim.takeWhile(c => c.isLetterOrDigit || c == '_')
          val rhsName = rhsCode.trim
          if (
            lhsName.nonEmpty &&
            rhsName.matches("[A-Za-z_]\\w*") &&
            pythonHttpClientVars.contains(rhsName) &&
            !pythonHttpClientVars.contains(lhsName)
          ) {
            pythonHttpClientVars.add(lhsName)
            grew = true
          }
        }
      }
    }
  }

  // Identifier-receiver regex used by the type-aware fallback. We pull
  // the first identifier of the form `<name>.` from the call's code text
  // and check it against `pythonHttpClientVars`.
  val pythonReceiverIdentifierRegex = """(?is)^\s*([A-Za-z_]\w*)\.""".r
  def filterJavascriptSinks(
    cwe: String,
    sinkClass: String,
    sinks: List[CallNode]
  ): List[CallNode] = {
    if (cwe == "CWE-79") {
      sinks.filter { call =>
        val name = if (call.name != null) call.name.toLowerCase else ""
        if (!xssAmbiguousCallNames.contains(name)) {
          true
        } else {
          val code = if (call.code != null) call.code else ""
          xssReceiver.matches(code)
        }
      }
    } else if (cwe == "CWE-915" || cwe == "CWE-639") {
      sinks.filter(call => firestoreReceiver.matches(callDescriptor(call)))
    } else if (cwe == "CWE-1321") {
      sinks.filter { call =>
        val name = if (call.name != null) call.name.toLowerCase else ""
        if (!protoPolluteAmbiguousNames.contains(name)) {
          true
        } else {
          protoPolluteReceiver.matches(callDescriptor(call))
        }
      }
    } else if (sinkClass == "ssti") {
      sinks.filter(call => jsSstiReceiver.matches(callDescriptor(call)))
    } else if (sinkClass == "nosql.query") {
      sinks.filter { call =>
        jsMongoReceiver.matches(callDescriptor(call)) ||
        jsMongoCollectionVars.contains(receiverCode(call))
      }
    } else if (sinkClass == "redos") {
      sinks.filter { call =>
        val code = if (call.code != null) call.code else ""
        jsRegExpConstructor.matches(code)
      }
    } else if (cwe == "CWE-918") {
      sinks.filter { call =>
        val code = if (call.code != null) call.code else ""
        val name = if (call.name != null) call.name.toLowerCase else ""
        ssrfBareNames.contains(name) || ssrfReceiver.matches(code)
      }
    } else sinks
  }

  def filterPythonSinks(cwe: String, sinkClass: String, sinks: List[CallNode]): List[CallNode] = {
    if (sinkClass == "nosql.query") {
      sinks.filter(call => pythonMongoReceiver.matches(callDescriptor(call)))
    } else if (sinkClass == "redos") {
      sinks.filter(call => pythonRegexReceiver.matches(callDescriptor(call)))
    } else if (cwe == "CWE-918") {
      sinks.filter { call =>
        val code = if (call.code != null) call.code else ""
        val name = if (call.name != null) call.name else ""
        if (pythonSsrfBareNames.contains(name) || pythonSsrfReceiver.matches(code)) {
          true
        } else {
          pythonReceiverIdentifierRegex.findFirstMatchIn(code) match {
            case Some(m) => pythonHttpClientVars.contains(m.group(1))
            case None => false
          }
        }
      }
    } else sinks
  }

  def filterJvmSinks(sinkClass: String, sinks: List[CallNode]): List[CallNode] = {
    if (sinkClass == "ssti") {
      sinks.filter(call => javaSstiReceiver.matches(callDescriptor(call)))
    } else if (sinkClass == "xpath.query") {
      sinks.filter(call => jvmXpathReceiver.matches(callDescriptor(call)))
    } else if (sinkClass == "ldap.query") {
      sinks.filter(call => jvmLdapReceiver.matches(callDescriptor(call)))
    } else sinks
  }

  def filterOtherLanguageSinks(sinkClass: String, sinks: List[CallNode]): List[CallNode] = {
    language.toLowerCase match {
      case "csharp" | "csharpsrc" if sinkClass == "redos" =>
        sinks.filter(call => csharpRegexReceiver.matches(callDescriptor(call)))
      case "csharp" | "csharpsrc" if sinkClass == "xpath.query" =>
        sinks.filter(call => csharpXpathReceiver.matches(callDescriptor(call)))
      case "php" if sinkClass == "xpath.query" =>
        sinks.filter { call =>
          val name = if (call.name != null) call.name.toLowerCase else ""
          name == "xpath" || phpXpathReceiver.matches(callDescriptor(call))
        }
      case "ruby" | "rubysrc" if sinkClass == "ssti" =>
        sinks.filter(call => rubyErbReceiver.matches(callDescriptor(call)))
      case "go" | "golang" if sinkClass == "ssti" =>
        sinks.filter(call => goTemplateReceiver.matches(callDescriptor(call)))
      case _ => sinks
    }
  }

  def restrictBuiltinSinks(cwe: String, sinkClass: String, sinks: List[CallNode]): List[CallNode] = {
    language.toLowerCase match {
      case "javascript" | "typescript" | "jssrc" =>
        filterJavascriptSinks(cwe, sinkClass, sinks)
      case "python" => filterPythonSinks(cwe, sinkClass, sinks)
      case "java" | "kotlin" => filterJvmSinks(sinkClass, sinks)
      case _ => filterOtherLanguageSinks(sinkClass, sinks)
    }
  }

  def indexedArguments(call: CallNode, indexes: Set[Int]) = {
    val selected = call.argument.l.filter(argument => indexes.contains(argument.argumentIndex))
    if (selected.nonEmpty) selected else call.argument.l
  }

  def isStaticValueArgument(argument: io.shiftleft.codepropertygraph.generated.nodes.Expression) = {
    val code = if (argument.code != null) argument.code.trim else ""
    val isLiteral =
      argument.isInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Literal]
    val isConstantIdentifier = code.matches("(?:[A-Za-z_]\\w*\\.)*[A-Z][A-Z0-9_]*")
    isLiteral || isConstantIdentifier
  }

  def dynamicArguments(call: CallNode, indexes: Set[Int]) =
    indexedArguments(call, indexes).filterNot(isStaticValueArgument)

  def sinkArguments(cwe: String, sinkClass: String, call: CallNode) = {
    val name = if (call.name != null) call.name.toLowerCase else ""
    val lang = language.toLowerCase
    if (sinkClass == "nosql.query" || sinkClass == "xpath.query") {
      dynamicArguments(call, Set(1))
    } else if (sinkClass == "header.write") {
      dynamicArguments(call, Set(1, 2))
    } else if (sinkClass == "ldap.query" && (lang == "java" || lang == "kotlin")) {
      dynamicArguments(call, Set(2))
    } else if (sinkClass == "ldap.query" && lang == "php") {
      dynamicArguments(call, Set(3))
    } else if (sinkClass == "ssti" && (lang == "java" || lang == "kotlin")) {
      val templateArgs =
        if (name == "evaluate") indexedArguments(call, Set(4))
        else indexedArguments(call, Set(2))
      templateArgs.filterNot(isStaticValueArgument)
    } else if (sinkClass == "ssti") {
      dynamicArguments(call, Set(1))
    } else if (sinkClass == "redos" && (lang == "csharp" || lang == "csharpsrc")) {
      if (name == "<init>") dynamicArguments(call, Set(1))
      else if (receiverCode(call).equalsIgnoreCase("Regex")) dynamicArguments(call, Set(2))
      // Instance IsMatch receives only the input string. A dynamic pattern is
      // already captured at Regex.<init>; treating the receiver as a second
      // pattern sink creates false flows through fixed static Regex fields.
      else call.argument.l.take(0)
    } else if (sinkClass == "redos") {
      dynamicArguments(call, Set(1))
    } else call.argument.l
  }

  val extensionSinkKeys: Set[(String, String, String)] =
    extensionSinks.toSet
  val w = new BufferedWriter(new FileWriter(outPath))
  try {
    for ((cwe, sinkClass, sinkPattern) <- sinkClasses) {
      val callCandidates = cpg.call.name(sinkPattern).l
      // Phase 5: extension-owned sinks bypass the built-in receiver filter
      // (restrictBuiltinSinks). Proposals are explicit about which call names
      // qualify; subjecting them to the built-in allowlist would block
      // arbitrary custom-client sinks like `apiv2_fetch` (no `httpx.`
      // receiver, no bare `fetch`/`request` name). When the extension
      // entry carries a receiver_regex, apply it as the per-entry filter.
      val isExtensionSink =
        extensionSinkKeys.contains((cwe, sinkClass, sinkPattern))
      val sinkCalls = if (isExtensionSink) {
        extensionReceiverMap.get((cwe, sinkClass, sinkPattern)) match {
          case Some(recvPattern) =>
            val r = recvPattern.r
            callCandidates.filter { c =>
              val code = if (c.code != null) c.code else ""
              r.findFirstIn(code).isDefined
            }
          case None => callCandidates
        }
      } else {
        restrictBuiltinSinks(cwe, sinkClass, callCandidates)
      }

      // ---- Pass 1: reachableByFlows on each sink's arguments ----
      for (call <- sinkCalls) {
        val sinkFile = fileOf(call)
        val sinkLine = lineOf(call)
        val args = sinkArguments(cwe, sinkClass, call)
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
                s""""sink_class":"$sinkClass","parameterization":"unknown",""" +
                s""""flow_type":"dataflow"}"""
              w.write(js)
              w.newLine()
            }
          }
        }
      }

      // ---- Pass 2: co-location fallback for sinks Pass 1 missed entirely ----
      // The fallback exists for closure-captured JS handlers where def/use
      // links are weak. It runs for every JS sink class under Recall-First
      // Invariant 6: every fallback emission carries flow_type=co-location so
      // ``ai_codescan.scoring.score_candidate`` can DEMOTE the candidate via
      // a strong negative factor without dropping it. Class-by-class fallback
      // deny lists are forbidden.
      val fallbackEnabled = language.toLowerCase == "javascript"
      val fallbackSinks = sinkCalls.filter { sink =>
        fallbackEnabled && sinkArguments(cwe, sinkClass, sink).nonEmpty
      }
      for (sink <- fallbackSinks) {
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
              s""""sink_class":"$sinkClass","parameterization":"unknown",""" +
              s""""flow_type":"co-location"}"""
            w.write(js)
            w.newLine()
          }
        }
        }  // end else (pass1 didn't cover this sink)
      }
    }

    // ---- JS DOM-XSS via property assignment ---------------------------------
    // ``el.innerHTML = userInput`` is NOT a call by name — it's lowered to a
    // ``<operator>.assignment`` whose LHS is a fieldAccess. The per-sinkClass
    // call-name loop above never sees it. We walk assignments whose LHS code
    // ends in a DOM sink field name and run reachableByFlows from the standard
    // source set to the RHS. Mirrors the Python HTTP-client assignment pre-pass.
    if (
      language.toLowerCase == "javascript" ||
      language.toLowerCase == "typescript" ||
      language.toLowerCase == "jssrc"
    ) {
      val domAssignRegex =
        """(?is).*\.(?:innerHTML|outerHTML|dangerouslySetInnerHTML)\s*$""".r
      val cwe = "CWE-79"
      val sinkClass = "html.write"
      cpg.call.name("<operator>.assignment").foreach { a =>
        try {
          val args = a.argument.l
          if (args.length >= 2) {
            val lhsCode = if (args.head.code != null) args.head.code.trim else ""
            if (domAssignRegex.findFirstIn(lhsCode).isDefined) {
              val rhs = List(args(1))
              val paths =
                try rhs.reachableByFlows(rawSources).l
                catch { case _: Throwable => Nil }
              for (path <- paths if path.elements.nonEmpty) {
                val srcNode = path.elements.head
                val srcFile = fileOf(srcNode)
                val srcLine = lineOf(srcNode)
                val sinkFile = fileOf(a)
                val sinkLine = lineOf(a)
                if (srcFile != sinkFile || srcLine != sinkLine) {
                  val key = (srcFile, srcLine, sinkFile, sinkLine, cwe)
                  if (!emitted.contains(key)) {
                    emitted.add(key)
                    val fid = "joern-" + sha1Short(
                      s"$srcFile:$srcLine:$sinkFile:$sinkLine:$cwe"
                    )
                    val sinkName = lhsCode.split("\\.").lastOption.getOrElse("innerHTML")
                    val js =
                      s"""{"fid":"$fid","source_file":"${escape(srcFile)}",""" +
                      s""""source_line":$srcLine,"sink_file":"${escape(sinkFile)}",""" +
                      s""""sink_line":$sinkLine,"source_name":"${escape(srcNode.code)}",""" +
                      s""""sink_name":"${escape(sinkName)}","cwe":"$cwe",""" +
                      s""""sink_class":"$sinkClass","parameterization":"unknown",""" +
                      s""""flow_type":"dataflow"}"""
                    w.write(js)
                    w.newLine()
                  }
                }
              }
            }
          }
        } catch { case _: Throwable => () }
      }
    }

    // ---- JS CSPT (Client-Side Path Traversal) -------------------------------
    // Phase 19. CSPT is the client-side cousin of path traversal: user input
    // lands in the PATH section of a URL the browser fetches. The sink looks
    // identical to SSRF (``fetch``/``axios.get``/etc.); the discriminator is
    // *structural* — the URL literal starts with ``/`` and contains no
    // ``?``/``#``/``&`` BEFORE the concatenation point. If the user input is
    // injected after a ``?`` it's a query-string parameter, not a path
    // segment, and CSPT does not apply.
    //
    // CWE-22 (path traversal) — the user's call: "it mirrors path traversal
    // closer than SSRF". Sink class ``cspt``.
    if (
      language.toLowerCase == "javascript" ||
      language.toLowerCase == "typescript" ||
      language.toLowerCase == "jssrc"
    ) {
      val cwe = "CWE-22"
      val sinkClass = "cspt"
      // The class also excludes ``$`` so greedy matching stops BEFORE the
      // ``${`` substitution marker on template literals — without the
      // exclusion the regex swallows past ``${userId}`` and the alternative
      // never fires.
      val csptShapeRegex =
        """(?s)['"`]/[^?#&'"`$]*(?:['"`]\s*\+|\$\{)""".r
      // HTTP-client call names whose first positional arg is the URL.
      val csptSinkNames = Set(
        "fetch", "request", "get", "post", "put", "delete", "patch", "head", "options"
      )
      cpg.call.filter { c =>
        val n = if (c.name != null) c.name.toLowerCase else ""
        csptSinkNames.contains(n)
      }.foreach { call =>
        try {
          // Match against the call's full source text. Joern's JS frontend
          // lowers template literals to ``<operator>.formatString`` calls; the
          // surface ``arg.code`` field can omit the original template form.
          // ``call.code`` is the unmodified source slice, so it contains both
          // the call name and the literal-prefix-then-concat shape we need.
          val callCode = if (call.code != null) call.code else ""
          if (csptShapeRegex.findFirstIn(callCode).isDefined) {
            val args = call.argument.l
            val paths =
              try args.reachableByFlows(rawSources).l
              catch { case _: Throwable => Nil }
            for (path <- paths if path.elements.nonEmpty) {
                val srcNode = path.elements.head
                val srcFile = fileOf(srcNode)
                val srcLine = lineOf(srcNode)
                val sinkFile = fileOf(call)
                val sinkLine = lineOf(call)
                if (srcFile != sinkFile || srcLine != sinkLine) {
                  val key = (srcFile, srcLine, sinkFile, sinkLine, cwe)
                  if (!emitted.contains(key)) {
                    emitted.add(key)
                    val fid = "joern-" + sha1Short(
                      s"$srcFile:$srcLine:$sinkFile:$sinkLine:$cwe:cspt"
                    )
                    val js =
                      s"""{"fid":"$fid","source_file":"${escape(srcFile)}",""" +
                      s""""source_line":$srcLine,"sink_file":"${escape(sinkFile)}",""" +
                      s""""sink_line":$sinkLine,"source_name":"${escape(srcNode.code)}",""" +
                      s""""sink_name":"${escape(call.name)}","cwe":"$cwe",""" +
                      s""""sink_class":"$sinkClass","parameterization":"unknown",""" +
                      s""""flow_type":"dataflow"}"""
                    w.write(js)
                    w.newLine()
                  }
                }
              }
            }
        } catch { case _: Throwable => () }
      }
    }
  } finally {
    w.close()
  }
}
