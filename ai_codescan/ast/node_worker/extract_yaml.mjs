import Parser from "tree-sitter";
import YAML from "@tree-sitter-grammars/tree-sitter-yaml";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

// @tree-sitter-grammars/tree-sitter-yaml exports the language object
// directly (no nested ``.language`` wrapper).
const parser = new Parser();
parser.setLanguage(YAML);

function syntheticId(file, kind, name, line) {
  return (
    "synthetic:" +
    createHash("sha1").update(`${file}|${kind}|${name}|${line}`).digest("hex").slice(0, 12)
  );
}

// Top-level keys we surface as symbols: the workflow / k8s / compose
// schema documents tend to carry meaningful entries at the root and one
// nesting level down (``jobs.<name>``, ``steps[i].name``, etc.). We
// emit symbols for the top-level mapping keys and call-shaped xrefs
// for ``run: …`` shell strings + ``${{ … }}`` template expressions so
// downstream taint regexes can pick them up.

function* descend(node, file) {
  // Process every block_mapping_pair we encounter, regardless of where
  // it sits in the tree. The YAML grammar wraps documents in stream /
  // ERROR / block_node containers and we want symbols + xrefs for *all*
  // mapping pairs (jobs.<name>, steps[i].name, run:, etc.).
  if (node.type === "block_mapping_pair") {
    const keyNode = node.childForFieldName?.("key");
    const valueNode = node.childForFieldName?.("value");
    const name = keyNode?.text?.trim() ?? "";
    if (name) {
      yield {
        type: "symbol",
        file,
        kind: "yaml_key",
        name,
        range: [node.startPosition.row + 1, node.endPosition.row + 1],
        syntheticId: syntheticId(file, "yaml_key", name, node.startPosition.row + 1),
      };
    }
    if (valueNode) {
      const valueText = valueNode.text;
      // ``run:`` blocks are shell-script bodies — surface them as a
      // call-shaped xref so entrypoint detectors can match (``run:`` is a
      // CLI marker; ``${{ … }}`` interpolated into ``run:`` is the
      // GitHub-Actions equivalent of a tainted shell argument).
      if (name === "run" || name === "shell") {
        yield {
          type: "xref",
          kind: "call",
          file,
          line: valueNode.startPosition.row + 1,
          callerSyntheticId: null,
          calleeText: `run: ${valueText}`,
        };
      }
      // ``on:`` is the workflow trigger. Surface as a call-shaped xref so
      // entrypoint detection can flag the workflow as an HTTP route /
      // event consumer.
      if (name === "on") {
        yield {
          type: "xref",
          kind: "call",
          file,
          line: valueNode.startPosition.row + 1,
          callerSyntheticId: null,
          calleeText: `on: ${valueText.split("\n", 1)[0].trim()}`,
        };
      }
      // Capture ``${{ ... }}`` template expressions anywhere — these are
      // the GitHub Actions taint sources / dispatchers worth surfacing.
      const exprMatches = valueText.match(/\$\{\{[^}]*\}\}/g);
      if (exprMatches) {
        for (const expr of exprMatches) {
          yield {
            type: "xref",
            kind: "call",
            file,
            line: valueNode.startPosition.row + 1,
            callerSyntheticId: null,
            calleeText: expr,
          };
        }
      }
    }
  }
  for (const child of node.namedChildren) yield* descend(child, file);
}

export async function* run(job) {
  for (const file of job.files) {
    const src = readFileSync(file, "utf8");
    const tree = parser.parse(src);
    yield { type: "file", file, lang: "yaml", lineCount: src.split("\n").length };
    yield* descend(tree.rootNode, file);
  }
}
