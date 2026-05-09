import Parser from "tree-sitter";
import Python from "tree-sitter-python";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const parser = new Parser();
parser.setLanguage(Python);

function syntheticId(file, kind, name, line) {
  return (
    "synthetic:" +
    createHash("sha1").update(`${file}|${kind}|${name}|${line}`).digest("hex").slice(0, 12)
  );
}

function* descend(node, file) {
  switch (node.type) {
    case "function_definition": {
      const nameNode = node.childForFieldName?.("name");
      const name = nameNode?.text ?? "<anonymous>";
      yield {
        type: "symbol",
        file,
        kind: "function",
        name,
        range: [node.startPosition.row + 1, node.endPosition.row + 1],
        syntheticId: syntheticId(file, "function", name, node.startPosition.row + 1),
      };
      break;
    }
    case "class_definition": {
      const nameNode = node.childForFieldName?.("name");
      const name = nameNode?.text ?? "<anonymous>";
      yield {
        type: "symbol",
        file,
        kind: "class",
        name,
        range: [node.startPosition.row + 1, node.endPosition.row + 1],
        syntheticId: syntheticId(file, "class", name, node.startPosition.row + 1),
      };
      break;
    }
    case "call":
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
    yield { type: "file", file, lang: "python", lineCount: src.split("\n").length };
    yield* descend(tree.rootNode, file);
  }
}
