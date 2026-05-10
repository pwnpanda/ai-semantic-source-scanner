import Parser from "tree-sitter";
import Kotlin from "tree-sitter-kotlin";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const parser = new Parser();
parser.setLanguage(Kotlin);

function syntheticId(file, kind, name, line) {
  return (
    "synthetic:" +
    createHash("sha1").update(`${file}|${kind}|${name}|${line}`).digest("hex").slice(0, 12)
  );
}

function* descend(node, file) {
  switch (node.type) {
    case "function_declaration":
    case "primary_constructor":
    case "secondary_constructor": {
      const nameNode = node.childForFieldName?.("name") ?? node.children.find((c) => c.type === "simple_identifier");
      const name = nameNode?.text ?? "<anonymous>";
      yield {
        type: "symbol",
        file,
        kind: node.type === "function_declaration" ? "function" : "constructor",
        name,
        range: [node.startPosition.row + 1, node.endPosition.row + 1],
        syntheticId: syntheticId(file, node.type, name, node.startPosition.row + 1),
      };
      break;
    }
    case "class_declaration":
    case "object_declaration":
    case "interface_declaration": {
      const nameNode = node.childForFieldName?.("name") ?? node.children.find((c) => c.type === "type_identifier");
      const name = nameNode?.text ?? "<anonymous>";
      yield {
        type: "symbol",
        file,
        kind: node.type.split("_")[0], // 'class' | 'object' | 'interface'
        name,
        range: [node.startPosition.row + 1, node.endPosition.row + 1],
        syntheticId: syntheticId(file, node.type, name, node.startPosition.row + 1),
      };
      break;
    }
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
    case "annotation":
      // Spring-on-Kotlin (@RestController, @GetMapping) etc — surface as
      // call-shaped xrefs so the entrypoint detector matches them by text.
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
    yield { type: "file", file, lang: "kotlin", lineCount: src.split("\n").length };
    yield* descend(tree.rootNode, file);
  }
}
