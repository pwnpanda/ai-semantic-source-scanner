// Phase 19 NEGATIVE — same source as the positive, but the user input is
// interpolated into the QUERY STRING (after `?`), not the URL path. The
// CSPT discriminator must NOT fire — recall-first invariant 5.

function loadProfile() {
    const userId = new URLSearchParams(location.search).get("user");
    fetch(`/api/profile?user=${userId}`)  // safe: user value is a query param
        .then((r) => r.json())
        .then((p) => renderProfile(p));
}

window.addEventListener("load", loadProfile);
