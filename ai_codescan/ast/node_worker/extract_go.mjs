import Parser from "tree-sitter";
import Go from "tree-sitter-go";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const parser = new Parser();
parser.setLanguage(Go);

function syntheticId(file, kind, name, line) {
  return (
    "synthetic:" +
    createHash("sha1").update(`${file}|${kind}|${name}|${line}`).digest("hex").slice(0, 12)
  );
}

function* descend(node, file) {
  switch (node.type) {
    case "function_declaration":
    case "method_declaration": {
      const nameNode = node.childForFieldName?.("name");
      const name = nameNode?.text ?? "<anonymous>";
      yield {
        type: "symbol",
        file,
        kind: node.type === "method_declaration" ? "method" : "function",
        name,
        range: [node.startPosition.row + 1, node.endPosition.row + 1],
        syntheticId: syntheticId(file, "function", name, node.startPosition.row + 1),
      };
      break;
    }
    case "type_declaration": {
      // A ``type Foo struct {...}`` may declare multiple specs in one block.
      for (const spec of node.namedChildren) {
        if (spec.type !== "type_spec") continue;
        const nameNode = spec.childForFieldName?.("name");
        const typeNode = spec.childForFieldName?.("type");
        const name = nameNode?.text ?? "<anonymous>";
        let kind = "type";
        if (typeNode?.type === "struct_type") kind = "struct";
        else if (typeNode?.type === "interface_type") kind = "interface";
        yield {
          type: "symbol",
          file,
          kind,
          name,
          range: [spec.startPosition.row + 1, spec.endPosition.row + 1],
          syntheticId: syntheticId(file, kind, name, spec.startPosition.row + 1),
        };
      }
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
    default:
      break;
  }
  for (const child of node.namedChildren) yield* descend(child, file);
}

export async function* run(job) {
  for (const file of job.files) {
    const src = readFileSync(file, "utf8");
    const tree = parser.parse(src);
    yield { type: "file", file, lang: "go", lineCount: src.split("\n").length };
    yield* descend(tree.rootNode, file);
  }
}
