import Parser from "tree-sitter";
import Ruby from "tree-sitter-ruby";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const parser = new Parser();
parser.setLanguage(Ruby);

function syntheticId(file, kind, name, line) {
  return (
    "synthetic:" +
    createHash("sha1").update(`${file}|${kind}|${name}|${line}`).digest("hex").slice(0, 12)
  );
}

function* descend(node, file) {
  switch (node.type) {
    case "method":
    case "singleton_method": {
      const nameNode = node.childForFieldName?.("name");
      const name = nameNode?.text ?? "<anonymous>";
      yield {
        type: "symbol",
        file,
        kind: node.type === "singleton_method" ? "singleton_method" : "method",
        name,
        range: [node.startPosition.row + 1, node.endPosition.row + 1],
        syntheticId: syntheticId(file, "method", name, node.startPosition.row + 1),
      };
      break;
    }
    case "class":
    case "module": {
      const nameNode = node.childForFieldName?.("name");
      const name = nameNode?.text ?? "<anonymous>";
      yield {
        type: "symbol",
        file,
        kind: node.type, // 'class' or 'module'
        name,
        range: [node.startPosition.row + 1, node.endPosition.row + 1],
        syntheticId: syntheticId(file, node.type, name, node.startPosition.row + 1),
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
    yield { type: "file", file, lang: "ruby", lineCount: src.split("\n").length };
    yield* descend(tree.rootNode, file);
  }
}
