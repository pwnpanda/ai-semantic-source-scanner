import Parser from "tree-sitter";
import ObjectiveC from "tree-sitter-objc";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const parser = new Parser();
parser.setLanguage(ObjectiveC);

function syntheticId(file, kind, name, line) {
  return (
    "synthetic:" +
    createHash("sha1").update(`${file}|${kind}|${name}|${line}`).digest("hex").slice(0, 12)
  );
}

function declarationName(node) {
  return node.childForFieldName?.("name")?.text ?? firstIdentifier(node) ?? "<anonymous>";
}

function firstIdentifier(node) {
  if (node.type === "identifier") return node.text;
  for (const child of node.namedChildren) {
    const identifier = firstIdentifier(child);
    if (identifier) return identifier;
  }
  return null;
}

function symbol(node, file, kind) {
  const name = declarationName(node);
  const line = node.startPosition.row + 1;
  return {
    type: "symbol",
    file,
    kind,
    name,
    range: [line, node.endPosition.row + 1],
    syntheticId: syntheticId(file, node.type, name, line),
  };
}

function* descend(node, file) {
  switch (node.type) {
    case "function_definition":
      yield symbol(node, file, "function");
      break;
    case "method_declaration":
    case "method_definition":
      yield symbol(node, file, "method");
      break;
    case "class_interface":
    case "class_implementation":
      yield symbol(node, file, "class");
      break;
    case "protocol_declaration":
      yield symbol(node, file, "protocol");
      break;
    case "call_expression":
    case "message_expression":
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
    const source = readFileSync(file, "utf8");
    const tree = parser.parse(source);
    yield { type: "file", file, lang: "objective-c", lineCount: source.split("\n").length };
    yield* descend(tree.rootNode, file);
  }
}
