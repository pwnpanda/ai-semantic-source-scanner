import { Project, SyntaxKind } from "ts-morph";
import { createHash } from "node:crypto";

function syntheticId(file, kind, name, line) {
  const hash = createHash("sha1").update(`${file}|${kind}|${name}|${line}`).digest("hex");
  return `synthetic:${hash.slice(0, 12)}`;
}

function recordSymbol(node, kind, displayName) {
  const sf = node.getSourceFile();
  const start = node.getStartLineNumber();
  const end = node.getEndLineNumber();
  const file = sf.getFilePath();
  return {
    type: "symbol",
    file,
    kind,
    name: displayName,
    range: [start, end],
    syntheticId: syntheticId(file, kind, displayName, start),
  };
}

export async function* run(job) {
  const tsconfigPath = job.tsconfig ?? null;
  const project = tsconfigPath
    ? new Project({ tsConfigFilePath: tsconfigPath, skipAddingFilesFromTsConfig: false })
    : new Project({ compilerOptions: { allowJs: true, target: 99 } });

  if (!tsconfigPath) {
    project.addSourceFilesAtPaths(job.files);
  }

  for (const sf of project.getSourceFiles()) {
    const file = sf.getFilePath();
    yield {
      type: "file",
      file,
      lang: sf.getExtension().slice(1),
      lineCount: sf.getEndLineNumber(),
    };

    for (const fn of sf.getFunctions()) {
      yield recordSymbol(fn, "function", fn.getName() ?? "<anonymous>");
    }
    for (const cls of sf.getClasses()) {
      yield recordSymbol(cls, "class", cls.getName() ?? "<anonymous>");
      for (const m of cls.getMethods()) {
        yield recordSymbol(m, "method", `${cls.getName() ?? "<anonymous>"}.${m.getName()}`);
      }
    }
    for (const v of sf.getVariableDeclarations()) {
      yield recordSymbol(v, "variable", v.getName());
    }

    for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const expr = call.getExpression();
      yield {
        type: "xref",
        kind: "call",
        file,
        line: call.getStartLineNumber(),
        callerSyntheticId: null,
        calleeText: expr.getText(),
      };
    }

    for (const imp of sf.getImportDeclarations()) {
      yield {
        type: "xref",
        kind: "import",
        file,
        line: imp.getStartLineNumber(),
        moduleSpecifier: imp.getModuleSpecifierValue(),
      };
    }
  }
}
