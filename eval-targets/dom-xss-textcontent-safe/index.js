// Negative eval target — Phase 16 (Recall-First Invariant 5).
// Same source as dom-xss-innerhtml, but rendered via textContent which
// does NOT parse HTML. The scanner must not report this.

function renderGreeting() {
    const name = location.hash.slice(1);
    const el = document.getElementById("greeting");
    el.textContent = "Hello, " + name;  // SAFE: textContent is plain text
}

renderGreeting();
