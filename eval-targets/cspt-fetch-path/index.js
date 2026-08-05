// Phase 19 positive — CSPT (Client-Side Path Traversal).
// Source: location.search (attacker-controlled query string).
// Sink: fetch with the user value spliced into the PATH section of the URL.
//
// userId = "../admin/secret" -> request goes to /api/admin/secret/profile
// (broken out of the /api/users/ prefix).

function loadProfile() {
    const userId = new URLSearchParams(location.search).get("user");
    fetch(`/api/users/${userId}/profile`)  // VULNERABLE: path-section concat
        .then((r) => r.json())
        .then((p) => renderProfile(p));
}

window.addEventListener("load", loadProfile);
