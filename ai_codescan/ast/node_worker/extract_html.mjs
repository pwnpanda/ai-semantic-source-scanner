import { parse } from "parse5";
import { readFileSync } from "node:fs";

function* walk(node, file, lineMap, ancestors) {
  if (!node) return;
  if (node.tagName === "script") {
    const start = node.sourceCodeLocation?.startLine ?? 0;
    const end = node.sourceCodeLocation?.endLine ?? start;
    const inline = node.childNodes?.[0]?.value ?? null;
    const srcAttr = node.attrs?.find((a) => a.name === "src")?.value ?? null;
    yield {
      type: "html_script",
      file,
      range: [start, end],
      src: srcAttr,
      inline,
    };
  }
  if (node.attrs) {
    for (const attr of node.attrs) {
      if (attr.name.startsWith("on")) {
        const loc = node.sourceCodeLocation?.attrs?.[attr.name];
        yield {
          type: "html_handler",
          file,
          tag: node.tagName,
          attr: attr.name,
          line: loc?.startLine ?? 0,
          js: attr.value,
        };
      }
    }
  }
  for (const child of node.childNodes ?? []) {
    yield* walk(child, file, lineMap, ancestors);
  }
}

export async function* run(job) {
  for (const file of job.files) {
    const html = readFileSync(file, "utf8");
    const doc = parse(html, { sourceCodeLocationInfo: true });
    yield { type: "file", file, lang: "html", lineCount: html.split("\n").length };
    yield* walk(doc, file, null, []);
  }
}
