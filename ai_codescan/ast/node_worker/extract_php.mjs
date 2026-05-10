import Parser from "tree-sitter";
import PHP from "tree-sitter-php";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

// tree-sitter-php exposes two grammars:
//   - ``php``: parses ``<?php ... ?>`` embedded in HTML/text (templates).
//   - ``php_only``: pure-PHP files, faster and less ambiguous.
// We pick by file extension: ``.phtml`` and any view templates use ``php``,
// everything else uses ``php_only``.
// tree-sitter-php exports ``{ php: <wrapper>, php_only: <wrapper> }``. Pass
// the wrapper itself to ``setLanguage`` (not the nested ``.language`` —
// that's a separate handle that node-bindings unmarshalling can't decode
// against the host ``tree-sitter@0.22.4``).
const phpOnlyParser = new Parser();
phpOnlyParser.setLanguage(PHP.php_only);
const phpEmbeddedParser = new Parser();
phpEmbeddedParser.setLanguage(PHP.php);

function parserForFile(_file) {
  // tree-sitter-php's ``php`` grammar covers both ``<?php ... ?>`` files and
  // mixed HTML+PHP, so we use it uniformly. ``php_only`` had ABI issues with
  // the pinned host (``tree-sitter@0.22.4``) on the published 0.23.x line.
  return phpEmbeddedParser;
}

function syntheticId(file, kind, name, line) {
  return (
    "synthetic:" +
    createHash("sha1").update(`${file}|${kind}|${name}|${line}`).digest("hex").slice(0, 12)
  );
}

function* descend(node, file) {
  switch (node.type) {
    case "function_definition":
    case "method_declaration": {
      const nameNode = node.childForFieldName?.("name");
      const name = nameNode?.text ?? "<anonymous>";
      yield {
        type: "symbol",
        file,
        kind: node.type === "method_declaration" ? "method" : "function",
        name,
        range: [node.startPosition.row + 1, node.endPosition.row + 1],
        syntheticId: syntheticId(file, node.type, name, node.startPosition.row + 1),
      };
      break;
    }
    case "class_declaration":
    case "interface_declaration":
    case "trait_declaration":
    case "enum_declaration": {
      const nameNode = node.childForFieldName?.("name");
      const name = nameNode?.text ?? "<anonymous>";
      yield {
        type: "symbol",
        file,
        kind: node.type.split("_")[0],
        name,
        range: [node.startPosition.row + 1, node.endPosition.row + 1],
        syntheticId: syntheticId(file, node.type, name, node.startPosition.row + 1),
      };
      break;
    }
    case "function_call_expression":
    case "member_call_expression":
    case "scoped_call_expression":
    case "object_creation_expression":
      yield {
        type: "xref",
        kind: "call",
        file,
        line: node.startPosition.row + 1,
        callerSyntheticId: null,
        calleeText: node.text,
      };
      break;
    case "attribute":
      // PHP 8 attributes (``#[Route('/path', methods: ['GET'])]``) — surface
      // as call-shaped xrefs so entrypoint detection can match by text.
      yield {
        type: "xref",
        kind: "call",
        file,
        line: node.startPosition.row + 1,
        callerSyntheticId: null,
        calleeText: node.text,
      };
      break;
    default:
      break;
  }
  for (const child of node.namedChildren) yield* descend(child, file);
}

export async function* run(job) {
  for (const file of job.files) {
    const src = readFileSync(file, "utf8");
    const tree = parserForFile(file).parse(src);
    yield { type: "file", file, lang: "php", lineCount: src.split("\n").length };
    yield* descend(tree.rootNode, file);
  }
}
