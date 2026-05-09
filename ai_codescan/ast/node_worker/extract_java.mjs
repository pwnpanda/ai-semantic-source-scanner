import Parser from "tree-sitter";
import Java from "tree-sitter-java";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const parser = new Parser();
parser.setLanguage(Java);

function syntheticId(file, kind, name, line) {
  return (
    "synthetic:" +
    createHash("sha1").update(`${file}|${kind}|${name}|${line}`).digest("hex").slice(0, 12)
  );
}

function* descend(node, file) {
  switch (node.type) {
    case "method_declaration":
    case "constructor_declaration": {
      const nameNode = node.childForFieldName?.("name");
      const name = nameNode?.text ?? "<anonymous>";
      yield {
        type: "symbol",
        file,
        kind: node.type === "constructor_declaration" ? "constructor" : "method",
        name,
        range: [node.startPosition.row + 1, node.endPosition.row + 1],
        syntheticId: syntheticId(file, "method", name, node.startPosition.row + 1),
      };
      break;
    }
    case "class_declaration":
    case "interface_declaration":
    case "enum_declaration":
    case "record_declaration": {
      const nameNode = node.childForFieldName?.("name");
      const name = nameNode?.text ?? "<anonymous>";
      yield {
        type: "symbol",
        file,
        kind: node.type.split("_")[0], // 'class' | 'interface' | 'enum' | 'record'
        name,
        range: [node.startPosition.row + 1, node.endPosition.row + 1],
        syntheticId: syntheticId(file, node.type, name, node.startPosition.row + 1),
      };
      break;
    }
    case "method_invocation":
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
    case "annotation":
    case "marker_annotation":
      // Surface annotation usages as call-style xrefs so entrypoint detection
      // (Spring @GetMapping / JAX-RS @Path / etc.) can match them by callee text.
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
    const tree = parser.parse(src);
    yield { type: "file", file, lang: "java", lineCount: src.split("\n").length };
    yield* descend(tree.rootNode, file);
  }
}
