"""Behavior matrix for the Phase 20/21 Joern detector catalog."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import pytest

JOERN_QUERY = Path(__file__).parents[1] / "ai_codescan/engines/joern_queries.sc"

RuleKey = tuple[str, str, str]


@dataclass(frozen=True, slots=True)
class DetectorRule:
    """Expected behavior of one language/CWE/sink-class detector family."""

    patterns: tuple[str, ...]
    positives: tuple[str, ...]
    negatives: tuple[str, ...]


_DETECTOR_MATRIX: dict[RuleKey, DetectorRule] = {
    ("kotlin", "CWE-611", "xml.parse"): DetectorRule(
        (
            r"(?i)^(parse|unmarshal|read)$",
            r"(?i)^createXMLStreamReader$",
        ),
        (
            "parse",
            "unmarshal",
            "read",
            "createXMLStreamReader",
        ),
        ("parseInt", "readText", "newDocumentBuilder", "newSAXParser"),
    ),
    ("kotlin", "CWE-93", "header.write"): DetectorRule(
        (r"(?i)^(setHeader|addHeader|addCookie)$",),
        ("setHeader", "addHeader", "addCookie"),
        ("setBody", "addAttribute"),
    ),
    ("kotlin", "CWE-532", "log.sensitive"): DetectorRule(
        (r"(?i)^(trace|debug|info|warn|error|fatal|severe)$",),
        ("trace", "debug", "info", "warn", "error", "fatal", "severe"),
        ("print", "format"),
    ),
    ("kotlin", "CWE-90", "ldap.query"): DetectorRule(
        (r"(?i)^search$",),
        ("search",),
        ("find", "lookup"),
    ),
    ("kotlin", "CWE-1336", "ssti"): DetectorRule(
        (r"(?i)^(evaluate|<init>)$",),
        ("evaluate", "<init>"),
        ("process", "getTemplate"),
    ),
    ("kotlin", "CWE-643", "xpath.query"): DetectorRule(
        (
            r"(?i)^(evaluate|compile|evaluateExpression|compileExpression|selectNodes|selectSingleNode)$",
        ),
        (
            "evaluate",
            "compile",
            "evaluateExpression",
            "compileExpression",
            "selectNodes",
            "selectSingleNode",
        ),
        ("select", "find"),
    ),
    ("csharp", "CWE-611", "xml.parse"): DetectorRule(
        (r"(?i)^(LoadXml|<init>)$",),
        ("LoadXml", "<init>"),
        ("LoadJson", "TextReader", "XmlTextReader", "XPathDocument"),
    ),
    ("csharp", "CWE-93", "header.write"): DetectorRule(
        (r"(?i)^(AppendHeader|AddHeader)$",),
        ("AppendHeader", "AddHeader"),
        ("AppendBody", "AddItem"),
    ),
    ("csharp", "CWE-532", "log.sensitive"): DetectorRule(
        (r"(?i)^(LogTrace|LogDebug|LogInformation|LogWarning|LogError|LogCritical)$",),
        (
            "LogTrace",
            "LogDebug",
            "LogInformation",
            "LogWarning",
            "LogError",
            "LogCritical",
        ),
        ("LogMetric", "WriteLine"),
    ),
    ("csharp", "CWE-90", "ldap.query"): DetectorRule(
        (r"(?i)^(FindOne|FindAll)$",),
        ("FindOne", "FindAll"),
        ("Find", "Single"),
    ),
    ("csharp", "CWE-643", "xpath.query"): DetectorRule(
        (r"(?i)^(Select|Evaluate|Compile|SelectNodes|SelectSingleNode)$",),
        ("Select", "Evaluate", "Compile", "SelectNodes", "SelectSingleNode"),
        ("Find", "Where"),
    ),
    ("csharp", "CWE-1333", "redos"): DetectorRule(
        (r"(?i)^(<init>|IsMatch)$",),
        ("<init>", "IsMatch"),
        ("Match", "Contains"),
    ),
    ("php", "CWE-611", "xml.parse"): DetectorRule(
        (r"(?i)^(simplexml_load_string|simplexml_load_file|loadXML|loadHTML)$",),
        ("simplexml_load_string", "simplexml_load_file", "loadXML", "loadHTML"),
        ("json_decode", "loadText"),
    ),
    ("php", "CWE-93", "header.write"): DetectorRule(
        (r"(?i)^header$",),
        ("header",),
        ("headers_list", "setcookie"),
    ),
    ("php", "CWE-93", "email.send"): DetectorRule(
        (r"(?i)^mail$",),
        ("mail",),
        ("email", "send"),
    ),
    ("php", "CWE-90", "ldap.query"): DetectorRule(
        (r"(?i)^(ldap_search|ldap_list|ldap_read)$",),
        ("ldap_search", "ldap_list", "ldap_read"),
        ("array_search", "ldap_bind"),
    ),
    ("php", "CWE-643", "xpath.query"): DetectorRule(
        (r"(?i)^(xpath|query|evaluate)$",),
        ("xpath", "query", "evaluate"),
        ("find", "search"),
    ),
    ("ruby", "CWE-611", "xml.parse"): DetectorRule(
        (r"(?i)^(XML|parse)$",),
        ("XML", "parse"),
        ("JSON", "parse_uri", "noent"),
    ),
    ("ruby", "CWE-93", "header.write"): DetectorRule(
        (r"(?i)^(set_header|headers)$",),
        ("set_header", "headers"),
        ("set_body", "header_value"),
    ),
    ("ruby", "CWE-1336", "ssti"): DetectorRule(
        (r"(?i)^initialize$",),
        ("initialize",),
        ("result", "result_with_hash", "format"),
    ),
    ("ruby", "CWE-93", "email.send"): DetectorRule(
        (r"(?i)^(deliver|deliver_now|deliver_later)$",),
        ("deliver", "deliver_now", "deliver_later"),
        ("send", "enqueue"),
    ),
    ("ruby", "CWE-532", "log.sensitive"): DetectorRule(
        (r"(?i)^(debug|info|warn|error|fatal)$",),
        ("debug", "info", "warn", "error", "fatal"),
        ("puts", "format"),
    ),
    ("go", "CWE-93", "header.write"): DetectorRule(
        (r"(?i)^(Set|Add)$",),
        ("Set", "Add"),
        ("Store", "Append"),
    ),
    ("go", "CWE-93", "email.send"): DetectorRule(
        (r"(?i)^SendMail$",),
        ("SendMail",),
        ("Send", "Mail"),
    ),
    ("go", "CWE-1336", "ssti"): DetectorRule(
        (r"(?i)^Parse$",),
        ("Parse",),
        ("ParseGlob", "ParseFiles", "Must", "ParseInt"),
    ),
    ("java", "CWE-611", "xml.parse"): DetectorRule(
        (
            r"(?i)^(parse|unmarshal|read)$",
            r"(?i)^createXMLStreamReader$",
        ),
        (
            "parse",
            "unmarshal",
            "read",
            "createXMLStreamReader",
        ),
        ("parseInt", "newBuilder", "newDocumentBuilder", "newSAXParser"),
    ),
    ("java", "CWE-93", "header.write"): DetectorRule(
        (r"(?i)^(setHeader|addHeader|addCookie)$",),
        ("setHeader", "addHeader", "addCookie"),
        ("setBody", "addAttribute"),
    ),
    ("java", "CWE-532", "log.sensitive"): DetectorRule(
        (r"(?i)^(trace|debug|info|warn|error|fatal|severe)$",),
        ("trace", "debug", "info", "warn", "error", "fatal", "severe"),
        ("print", "format"),
    ),
    ("java", "CWE-1336", "ssti"): DetectorRule(
        (r"(?i)^(evaluate|<init>)$",),
        ("evaluate", "<init>"),
        ("mergeTemplate", "process", "getTemplate", "render"),
    ),
    ("java", "CWE-643", "xpath.query"): DetectorRule(
        (
            r"(?i)^(evaluate|compile|evaluateExpression|compileExpression|selectNodes|selectSingleNode)$",
        ),
        (
            "evaluate",
            "compile",
            "evaluateExpression",
            "compileExpression",
            "selectNodes",
            "selectSingleNode",
        ),
        ("find", "search"),
    ),
    ("java", "CWE-90", "ldap.query"): DetectorRule(
        (r"(?i)^(search|searchControls)$",),
        ("search", "searchControls"),
        ("find", "lookup"),
    ),
    ("python", "CWE-611", "xml.parse"): DetectorRule(
        (r"(?i)^(fromstring|parseString|parse)$",),
        ("fromstring", "parseString", "parse"),
        ("from_json", "parse_qs", "XMLParser", "XMLPullParser"),
    ),
    ("python", "CWE-532", "log.sensitive"): DetectorRule(
        (r"(?i)^(debug|info|warning|warn|error|critical|exception)$",),
        ("debug", "info", "warning", "warn", "error", "critical", "exception"),
        ("print", "format"),
    ),
    ("python", "CWE-943", "nosql.query"): DetectorRule(
        (
            r"(?i)^(find|find_one|find_one_and_update|find_one_and_delete|aggregate|map_reduce|distinct)$",
        ),
        (
            "find",
            "find_one",
            "find_one_and_update",
            "find_one_and_delete",
            "aggregate",
            "map_reduce",
            "distinct",
        ),
        ("findall", "search"),
    ),
    ("python", "CWE-90", "ldap.query"): DetectorRule(
        (r"(?i)^(search_s|search_ext_s|search_st)$",),
        ("search_s", "search_ext_s", "search_st"),
        ("search", "find"),
    ),
    ("python", "CWE-643", "xpath.query"): DetectorRule(
        (r"(?i)^(xpath|iterfind)$",),
        ("xpath", "iterfind"),
        ("find", "search"),
    ),
    ("python", "CWE-1333", "redos"): DetectorRule(
        (r"(?i)^compile$",),
        ("compile",),
        ("search", "findall"),
    ),
    ("javascript", "CWE-93", "header.write"): DetectorRule(
        (r"(?i)^(setHeader|append)$",),
        ("setHeader", "append"),
        ("header", "set"),
    ),
    ("javascript", "CWE-1321", "proto.pollute"): DetectorRule(
        (
            r"(?i)^(merge|mergeWith|defaultsDeep|extend|deepmerge)$",
            r"(?i)^(set|setWith)$",
        ),
        ("merge", "mergeWith", "defaultsDeep", "extend", "deepmerge", "set", "setWith"),
        ("assign", "update"),
    ),
    ("javascript", "CWE-943", "nosql.query"): DetectorRule(
        (
            r"(?i)^(find|findOne|findOneAndUpdate|findOneAndDelete|findOneAndReplace)$",
            r"(?i)^(updateMany|deleteMany|countDocuments|aggregate|mapReduce|distinct)$",
        ),
        (
            "find",
            "findOne",
            "findOneAndUpdate",
            "findOneAndDelete",
            "findOneAndReplace",
            "updateMany",
            "deleteMany",
            "countDocuments",
            "aggregate",
            "mapReduce",
            "distinct",
        ),
        ("filter", "search"),
    ),
    ("javascript", "CWE-1336", "ssti"): DetectorRule(
        (r"(?i)^(compile|template)$",),
        ("compile", "template"),
        ("render", "format"),
    ),
    ("javascript", "CWE-1333", "redos"): DetectorRule(
        (r"(?i)^(RegExp|<operator>\.new)$",),
        ("RegExp", "<operator>.new"),
        ("match", "search"),
    ),
}

_EXPECTED_LANGUAGES_BY_FAMILY = {
    "email.send": {"go", "php", "ruby"},
    "header.write": {"csharp", "go", "java", "javascript", "kotlin", "php", "ruby"},
    "ldap.query": {"csharp", "java", "kotlin", "php", "python"},
    "log.sensitive": {"csharp", "java", "kotlin", "python", "ruby"},
    "nosql.query": {"javascript", "python"},
    "proto.pollute": {"javascript"},
    "redos": {"csharp", "javascript", "python"},
    "ssti": {"go", "java", "javascript", "kotlin", "ruby"},
    "xml.parse": {"csharp", "java", "kotlin", "php", "python", "ruby"},
    "xpath.query": {"csharp", "java", "kotlin", "php", "python"},
}

_CASE_RE = re.compile(r"^\s*case\s+(?P<labels>.+?)\s*=>\s*$", re.MULTILINE)
_TUPLE_RE = re.compile(
    r'\(\s*"(?P<cwe>CWE-\d+)",\s*"(?P<sink_class>[^"]+)",\s*'
    r'"(?P<pattern>(?:\\.|[^"])*)"\s*\)'
)


def _unescape_scala_string(value: str) -> str:
    return value.replace(r"\"", '"').replace(r"\\", "\\")


def _language_blocks(source: str) -> dict[str, str]:
    source = source[: source.index("val sourceNamePattern")]
    matches = list(_CASE_RE.finditer(source))
    blocks: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
        labels = re.findall(r'"([^"]+)"', match.group("labels"))
        block = source[match.end() : end]
        for label in labels:
            blocks[label] = block
    return blocks


def _catalog() -> dict[RuleKey, tuple[str, ...]]:
    blocks = _language_blocks(JOERN_QUERY.read_text(encoding="utf-8"))
    catalog: dict[RuleKey, tuple[str, ...]] = {}
    for language in {key[0] for key in _DETECTOR_MATRIX}:
        rules: dict[tuple[str, str], list[str]] = {}
        for match in _TUPLE_RE.finditer(blocks[language]):
            key = (match.group("cwe"), match.group("sink_class"))
            rules.setdefault(key, []).append(_unescape_scala_string(match.group("pattern")))
        for (cwe, sink_class), patterns in rules.items():
            catalog[(language, cwe, sink_class)] = tuple(patterns)
    return catalog


@pytest.mark.parametrize(("key", "rule"), _DETECTOR_MATRIX.items(), ids=str)
def test_phase_20_21_detector_names_match_language_matrix(
    key: RuleKey,
    rule: DetectorRule,
) -> None:
    patterns = _catalog()[key]

    assert patterns == rule.patterns
    for name in rule.positives:
        assert any(re.fullmatch(pattern, name) for pattern in patterns), (key, name)
    for name in rule.negatives:
        assert not any(re.fullmatch(pattern, name) for pattern in patterns), (key, name)


def test_phase_20_21_language_matrix_covers_every_added_family() -> None:
    actual: dict[str, set[str]] = {}
    for language, _cwe, sink_class in _DETECTOR_MATRIX:
        actual.setdefault(sink_class, set()).add(language)

    assert actual == _EXPECTED_LANGUAGES_BY_FAMILY


def _named_scala_regex(name: str) -> re.Pattern[str]:
    source = JOERN_QUERY.read_text(encoding="utf-8")
    declaration = re.search(rf"val {name}\s*=", source)
    assert declaration is not None, name
    expression = source[declaration.end() :]
    terminator = re.search(r'(?:\)|""")\.r', expression)
    assert terminator is not None, name
    fragments = re.findall(r'"""(.*?)"""', expression[: terminator.end()], re.DOTALL)
    assert fragments, name
    return re.compile("".join(fragments))


@pytest.mark.parametrize(
    "code",
    (
        "_.set(target, path, req.body)",
        "lodash.setWith(target, key, req.body, customizer)",
        "objectPath.set(target, path, req.body)",
        "dotProp.set(target, path, req.body)",
    ),
)
def test_prototype_pollution_receiver_gate_accepts_deep_set_helpers(code: str) -> None:
    assert _named_scala_regex("protoPolluteReceiver").fullmatch(code)


@pytest.mark.parametrize(
    "code",
    (
        "db.collection('users').doc(id).set(req.body)",
        "Object.create(req.body)",
        "cache.set(key, req.body)",
        "set(target, path, req.body)",
    ),
)
def test_prototype_pollution_receiver_gate_rejects_unrelated_set_calls(code: str) -> None:
    assert _named_scala_regex("protoPolluteReceiver").fullmatch(code) is None


@pytest.mark.parametrize(
    "code",
    (
        "db.collection('users').doc(id).update(req.body)",
        "firestore.collection('users').doc(id).set(req.body)",
        "docRef.create(req.body)",
        "collectionRef.doc(id)",
    ),
)
def test_firestore_receiver_gate_accepts_document_operations(code: str) -> None:
    assert _named_scala_regex("firestoreReceiver").fullmatch(code)


@pytest.mark.parametrize(
    "code",
    (
        "Object.create(req.body)",
        "cache.set(key, req.body)",
        "db.update('users', req.body)",
        "record.update(req.body)",
        "create(req.body)",
    ),
)
def test_firestore_receiver_gate_rejects_unrelated_mutators(code: str) -> None:
    assert _named_scala_regex("firestoreReceiver").fullmatch(code) is None


@pytest.mark.parametrize(
    ("regex_name", "positives", "negatives"),
    (
        (
            "jsSstiReceiver",
            (
                "handlebars:compile Handlebars.compile(input)",
                "<unknown>.compile hbs.compile(input)",
                "lodash:template lodash.template(input)",
                "nunjucks.compile(input)",
            ),
            ("ajv:compile validator.compile(input)", "WebAssembly:compile(input)"),
        ),
        (
            "jsEmailReceiver",
            (
                "nodemailer.Transport.sendMail mailer.sendMail(message)",
                "aws.SES.sendEmail sesClient.sendEmail(message)",
                "<unknown>.sendMail transporter.sendMail(message)",
                "<unknown>.sendMail transport.sendMail(message)",
            ),
            (
                "NotificationService.sendEmail notifications.sendEmail(message)",
                "queue.sendMail(message)",
                "HttpTransport.sendMail httpTransport.sendMail(message)",
                "transportQueue.sendMail(message)",
            ),
        ),
        (
            "jsHeaderReceiver",
            (
                "http.ServerResponse.setHeader res.setHeader(name, value)",
                "express.Response.append response.append(name, value)",
            ),
            (
                "FormData.append formData.append(name, value)",
                "Array.append values.append(value)",
            ),
        ),
        (
            "jsMongoReceiver",
            (
                "mongodb:collection.find users.find(input)",
                "mongoose.Model.findOne(input)",
            ),
            (
                "__ecma.Array:find values.find(input)",
                "SearchService.findOne(input)",
                "analytics.aggregate(input)",
            ),
        ),
        (
            "javaSstiReceiver",
            (
                "org.apache.velocity.app.VelocityEngine.evaluate evaluate(...) engine",
                "freemarker.template.Template.<init> new Template(...) template",
            ),
            (
                "freemarker.template.Template.process process(model, writer)",
                "freemarker.template.Configuration.getTemplate getTemplate(name)",
            ),
        ),
        (
            "jvmXmlReceiver",
            (
                "javax.xml.parsers.DocumentBuilder.parse builder.parse(input)",
                "org.xml.sax.XMLReader.parse xmlReader.parse(input)",
            ),
            (
                "com.fasterxml.jackson.core.JsonParser.read parser.read(input)",
                "com.example.CsvParser.parse parser.parse(input)",
            ),
        ),
        (
            "jvmLoggerReceiver",
            (
                "org.slf4j.Logger.info logger.info(secret)",
                "org.apache.logging.log4j.Logger.error auditLogger.error(secret)",
            ),
            (
                "com.example.Status.info status.info(secret)",
                "com.example.Catalog.error catalog.error(secret)",
            ),
        ),
        (
            "jvmXpathReceiver",
            ("javax.xml.xpath.XPath.evaluate xpath.evaluate(expr, doc)",),
            ("org.apache.velocity.app.VelocityEngine.evaluate engine.evaluate(...) ",),
        ),
        (
            "jvmLdapReceiver",
            ("javax.naming.directory.DirContext.search context.search(base, filter)",),
            ("com.example.SearchService.search service.search(term)",),
        ),
        (
            "csharpRegexReceiver",
            ("Regex.<init> new Regex(pattern)", "Regex.IsMatch Regex.IsMatch(input, pattern)"),
            ("Validator.IsMatch validator.IsMatch(input)",),
        ),
        (
            "csharpXpathReceiver",
            (
                "System.Xml.XPath.XPathNavigator.Select navigator.Select(expression)",
                "XmlDocument.SelectNodes document.SelectNodes(expression)",
            ),
            ("System.Linq.Enumerable.Select values.Select(projector)",),
        ),
        (
            "pythonRegexReceiver",
            ("re.py:<module>.compile re.compile(value)", "regex.compile(value)"),
            ("__builtin.compile compile(value, '<input>', 'eval')",),
        ),
        (
            "pythonMongoReceiver",
            (
                "pymongo.Collection.find users.find(value)",
                "motor.collection.find_one(value)",
            ),
            (
                "__builtin.str.find value.find(needle)",
                "SearchService.find_one(value)",
            ),
        ),
        (
            "pythonXmlReceiver",
            (
                "lxml.etree.fromstring etree.fromstring(input)",
                "xml.sax.parse xml.sax.parse(input)",
                "<unknown>.parse xml_parser.parse(input)",
            ),
            (
                "json.parse json.parse(input)",
                "csv.Parser.parse parser.parse(input)",
                "defusedxml.ElementTree.parse safe_xml.parse(input)",
            ),
        ),
        (
            "pythonLoggerReceiver",
            (
                "logging.Logger.error logger.error(secret)",
                "structlog.BoundLogger.info audit_logger.info(secret)",
            ),
            (
                "Response.error response.error(secret)",
                "Catalog.info catalog.info(secret)",
            ),
        ),
        (
            "phpXpathReceiver",
            (
                "DOMXPath.query $engine->query($expression)",
                "$xpathEvaluator->evaluate($expression)",
            ),
            ("Database.query $db->query($expression)", "$evaluator->evaluate($expression)"),
        ),
        (
            "rubyErbReceiver",
            ("erb.ERB.initialize ERB.new(source)",),
            ("json.initialize JSON.new(source)",),
        ),
        (
            "rubyXmlReceiver",
            (
                "nokogiri.Nokogiri.XML Nokogiri::XML(input)",
                "rexml.REXML.Document.parse xml_parser.parse(input)",
            ),
            ("json.JSON.parse JSON.parse(input)", "csv.CSV.parse CSV.parse(input)"),
        ),
        (
            "rubyLoggerReceiver",
            ("logger.Logger.info logger.info(secret)", "Rails.logger.error(secret)"),
            ("Result.info result.info(secret)", "Catalog.error catalog.error(secret)"),
        ),
        (
            "csharpXmlReceiver",
            (
                "System.Xml.XmlDocument.LoadXml document.LoadXml(input)",
                "System.Xml.XPath.XPathDocument.<init> new XPathDocument(input)",
            ),
            (
                "Newtonsoft.Json.JsonConvert.LoadXml serializer.LoadXml(input)",
                "System.Xml.XmlQualifiedName.<init> new XmlQualifiedName(input)",
            ),
        ),
        (
            "phpXmlReceiver",
            ("simplexml_load_string($input)", "DOMDocument $xml->loadXML($input)"),
            ("JsonDocument $document->loadXML($input)",),
        ),
        (
            "goTemplateReceiver",
            ("html/template.New.<ReturnType>.Parse template.New('x').Parse(source)",),
            (
                "html/template.ParseFiles template.ParseFiles(source)",
                "strconv.ParseInt strconv.ParseInt(source, 10, 64)",
            ),
        ),
        (
            "goHeaderReceiver",
            (
                (
                    "net/http.ResponseWriter.Header.<ReturnType>.<unknown>.Set "
                    "writer.Header().Set(name, value)"
                ),
                "net/http.Header.Add header.Add(name, value)",
            ),
            (
                "example.Cache.Set cache.Set(name, value)",
                "example.Header.Set header.Set(name, value)",
                "example.Collection.Add collection.Add(value)",
            ),
        ),
    ),
)
def test_ambiguous_sink_receiver_gates_match_security_apis_only(
    regex_name: str,
    positives: tuple[str, ...],
    negatives: tuple[str, ...],
) -> None:
    receiver = _named_scala_regex(regex_name)

    assert all(receiver.fullmatch(value) for value in positives)
    assert all(receiver.fullmatch(value) is None for value in negatives)


def test_javascript_regexp_constructor_gate_rejects_other_constructors() -> None:
    constructor = _named_scala_regex("jsRegExpConstructor")

    assert constructor.fullmatch("new RegExp(request.query.pattern)")
    assert constructor.fullmatch("RegExp(request.query.pattern)")
    assert constructor.fullmatch("new URL(request.query.url)") is None


def test_go_standard_regexp_is_not_modelled_as_redos() -> None:
    catalog = _catalog()

    assert ("go", "CWE-1333", "redos") not in catalog


def test_go_request_source_gate_uses_api_type_not_variable_name() -> None:
    source = _named_scala_regex("goRequestSourceFullName")

    assert source.fullmatch("net/http.Request.FormValue")
    assert source.fullmatch("github.com/gin-gonic/gin.Context.Query")
    assert source.fullmatch("example.Cache.FormValue") is None
