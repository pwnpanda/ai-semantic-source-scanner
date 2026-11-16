import Parser from "tree-sitter";
import Swift from "tree-sitter-swift";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const parser = new Parser();
parser.setLanguage(Swift);

function syntheticId(file, kind, name, line) {
  return (
    "synthetic:" +
    createHash("sha1").update(`${file}|${kind}|${name}|${line}`).digest("hex").slice(0, 12)
  );
}

function declarationName(node) {
  if (node.type === "init_declaration") return "init";
  return (
    node.childForFieldName?.("name")?.text ??
    node.namedChildren.find((child) =>
      ["simple_identifier", "type_identifier"].includes(child.type),
    )?.text ??
    "<anonymous>"
  );
}

function swiftTypeKind(node) {
  return (
    node.children.find((child) => ["actor", "class", "enum", "struct"].includes(child.type))
      ?.type ?? "class"
  );
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
    case "function_declaration":
    case "protocol_function_declaration":
      yield symbol(node, file, "function");
      break;
    case "init_declaration":
      yield symbol(node, file, "constructor");
      break;
    case "class_declaration":
      yield symbol(node, file, swiftTypeKind(node));
      break;
    case "protocol_declaration":
      yield symbol(node, file, "protocol");
      break;
    case "call_expression":
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
    yield { type: "file", file, lang: "swift", lineCount: source.split("\n").length };
    yield* descend(tree.rootNode, file);
  }
}
