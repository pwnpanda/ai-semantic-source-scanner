// Minimal pure-JS DOM-XSS target — Phase 16 positive eval.
// Source: location.hash (attacker-controlled, served from the URL).
// Sink: assignment into el.innerHTML — the property-assignment shape
// the post-loop scan in joern_queries.sc was added to catch.

function renderGreeting() {
    const name = location.hash.slice(1);
    const el = document.getElementById("greeting");
    el.innerHTML = "Hello, " + name;  // VULNERABLE: name is attacker-controlled HTML
}

renderGreeting();
