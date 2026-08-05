// Phase 16 positive eval — dynamic code execution from a DOM source.
// Source: location.search (the URL query string).
// Sink: eval() — caught by the call-name pattern (?i)^eval$ added to the
// JS sinkClasses, mapped to CWE-94 code.exec.

function runQueryFunction() {
    const expr = new URLSearchParams(location.search).get("expr");
    return eval(expr);  // VULNERABLE: attacker-controlled JS is executed
}

window.addEventListener("load", runQueryFunction);
