import Parser from "tree-sitter";
import CSharp from "tree-sitter-c-sharp";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const parser = new Parser();
parser.setLanguage(CSharp);

function syntheticId(file, kind, name, line) {
  return (
    "synthetic:" +
    createHash("sha1").update(`${file}|${kind}|${name}|${line}`).digest("hex").slice(0, 12)
  );
}

function* descend(node, file) {
  switch (node.type) {
    case "method_declaration":
    case "constructor_declaration":
    case "local_function_statement": {
      const nameNode = node.childForFieldName?.("name");
      const name = nameNode?.text ?? "<anonymous>";
      yield {
        type: "symbol",
        file,
        kind:
          node.type === "constructor_declaration"
            ? "constructor"
            : node.type === "local_function_statement"
              ? "local_function"
              : "method",
        name,
        range: [node.startPosition.row + 1, node.endPosition.row + 1],
        syntheticId: syntheticId(file, node.type, name, node.startPosition.row + 1),
      };
      break;
    }
    case "class_declaration":
    case "interface_declaration":
    case "record_declaration":
    case "struct_declaration":
    case "enum_declaration": {
      const nameNode = node.childForFieldName?.("name");
      const name = nameNode?.text ?? "<anonymous>";
      yield {
        type: "symbol",
        file,
        kind: node.type.split("_")[0], // 'class' | 'interface' | 'record' | 'struct' | 'enum'
        name,
        range: [node.startPosition.row + 1, node.endPosition.row + 1],
        syntheticId: syntheticId(file, node.type, name, node.startPosition.row + 1),
      };
      break;
    }
    case "invocation_expression":
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
      // ASP.NET attribute routing (``[HttpGet]`` / ``[Route(...)]``) and
      // Azure Functions ``[Function]`` markers — surface as call-shaped
      // xrefs so entrypoint detection can match them by callee text.
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
    yield { type: "file", file, lang: "csharp", lineCount: src.split("\n").length };
    yield* descend(tree.rootNode, file);
  }
}
