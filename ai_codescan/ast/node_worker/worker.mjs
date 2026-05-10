#!/usr/bin/env node
// Worker reads one JSON job per stdin line, writes JSONL records to stdout.
// Job: { kind: "ts" | "html" | "treesitter" | "python" | "java",
//        projectRoot, files: [...], tsconfig?: string }
// Output records: { type, file, ... }; one terminator { type: "done", jobId } per job.

import { createInterface } from "node:readline";

async function dispatch(job) {
  switch (job.kind) {
    case "ts": {
      const m = await import("./extract_ts.mjs");
      return m.run(job);
    }
    case "html": {
      const m = await import("./extract_html.mjs");
      return m.run(job);
    }
    case "treesitter": {
      const m = await import("./extract_treesitter.mjs");
      return m.run(job);
    }
    case "python": {
      const m = await import("./extract_python.mjs");
      return m.run(job);
    }
    case "java": {
      const m = await import("./extract_java.mjs");
      return m.run(job);
    }
    case "go": {
      const m = await import("./extract_go.mjs");
      return m.run(job);
    }
    case "ruby": {
      const m = await import("./extract_ruby.mjs");
      return m.run(job);
    }
    case "php": {
      const m = await import("./extract_php.mjs");
      return m.run(job);
    }
    case "csharp": {
      const m = await import("./extract_csharp.mjs");
      return m.run(job);
    }
    case "kotlin": {
      const m = await import("./extract_kotlin.mjs");
      return m.run(job);
    }
    case "bash": {
      const m = await import("./extract_bash.mjs");
      return m.run(job);
    }
    default:
      throw new Error(`unknown kind: ${job.kind}`);
  }
}

const rl = createInterface({ input: process.stdin });
for await (const line of rl) {
  if (!line.trim()) continue;
  let job;
  try {
    job = JSON.parse(line);
  } catch (e) {
    process.stdout.write(JSON.stringify({ type: "error", message: String(e) }) + "\n");
    continue;
  }
  try {
    const iter = await dispatch(job);
    for await (const record of iter) {
      process.stdout.write(JSON.stringify(record) + "\n");
    }
    process.stdout.write(JSON.stringify({ type: "done", jobId: job.jobId ?? null }) + "\n");
  } catch (e) {
    process.stdout.write(
      JSON.stringify({ type: "error", jobId: job.jobId ?? null, message: String(e) }) + "\n",
    );
  }
}
