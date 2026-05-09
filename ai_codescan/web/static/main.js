import React, { useCallback, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  MiniMap,
  applyNodeChanges,
  applyEdgeChanges,
} from "@xyflow/react";

const e = React.createElement;

// ---------------------------------------------------------------------------
// Layout: deterministic two-column placement (sources left, sinks right).
// Cheap, predictable, doesn't fight with the user's pan/zoom.
// ---------------------------------------------------------------------------
function layout(nodes) {
  const sources = nodes.filter((n) => n.kind === "source");
  const sinks = nodes.filter((n) => n.kind === "sink");
  const STEP = 90;
  const positioned = [];
  sources.forEach((n, i) => {
    positioned.push({
      ...n,
      type: "default",
      position: { x: 40, y: 40 + i * STEP },
      data: { label: e("div", { className: "node node-source" }, [
        e("label", { key: "l" }, n.label),
        e("div", { key: "k", className: "sub" }, n.tid || ""),
      ]) },
    });
  });
  sinks.forEach((n, i) => {
    positioned.push({
      ...n,
      type: "default",
      position: { x: 480, y: 40 + i * STEP },
      data: { label: e("div", { className: "node node-sink" }, [
        e("label", { key: "l" }, n.label),
        e("div", { key: "k", className: "sub" }, n.sid || ""),
      ]) },
    });
  });
  return positioned;
}

function App() {
  const [data, setData] = useState({ nodes: [], edges: [], flows: [] });
  const [filter, setFilter] = useState("");
  const [selected, setSelected] = useState(null);
  const [notes, setNotes] = useState([]);
  const [draft, setDraft] = useState("");

  const refresh = useCallback(async () => {
    const params = new URLSearchParams();
    if (filter) params.set("cwe", filter);
    const r = await fetch("/api/flows?" + params.toString());
    setData(await r.json());
  }, [filter]);

  useEffect(() => { refresh(); }, [refresh]);

  const nodes = useMemo(() => layout(data.nodes || []), [data.nodes]);
  const edges = useMemo(
    () => (data.edges || []).map((x) => ({
      id: x.id,
      source: x.source,
      target: x.target,
      label: x.cwe || "",
      style: { stroke: x.confidence === "definite" ? "#2746d3" : "#999" },
      labelStyle: { fontSize: 10 },
      animated: x.confidence === "definite",
    })),
    [data.edges],
  );

  const onNodesChange = useCallback(() => {}, []);
  const onEdgesChange = useCallback(() => {}, []);

  const loadNotes = useCallback(async (symbolId) => {
    const r = await fetch("/api/notes/" + encodeURIComponent(symbolId));
    const j = await r.json();
    setNotes(j.notes || []);
  }, []);

  const onNodeClick = useCallback((_evt, node) => {
    setSelected(node);
    setDraft("");
    const symId = node.tid || node.sid || node.id;
    loadNotes(symId);
  }, [loadNotes]);

  const saveNote = useCallback(async () => {
    if (!selected || !draft.trim()) return;
    const symId = selected.tid || selected.sid || selected.id;
    await fetch("/api/notes", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ symbol_id: symId, content: draft, layer: "human" }),
    });
    setDraft("");
    loadNotes(symId);
  }, [selected, draft, loadNotes]);

  const deleteNote = useCallback(async (rowid) => {
    await fetch("/api/notes/" + rowid, { method: "DELETE" });
    if (selected) {
      const symId = selected.tid || selected.sid || selected.id;
      loadNotes(symId);
    }
  }, [selected, loadNotes]);

  const cwes = useMemo(() => {
    const s = new Set();
    (data.flows || []).forEach((f) => f.cwe && s.add(f.cwe));
    return Array.from(s).sort();
  }, [data.flows]);

  return e("div", { className: "app" },
    e("header", null,
      e("h1", null, "ai-codescan flows"),
      e("span", { className: "stats" },
        `${data.nodes?.length || 0} nodes · ${data.edges?.length || 0} edges · ${data.flows?.length || 0} flows`),
      e("input", {
        placeholder: "filter by CWE (e.g. CWE-89)",
        value: filter,
        onChange: (ev) => setFilter(ev.target.value),
        list: "cwes",
        onKeyDown: (ev) => { if (ev.key === "Enter") refresh(); },
      }),
      e("datalist", { id: "cwes" }, cwes.map((c) => e("option", { key: c, value: c }))),
      e("button", { onClick: refresh, style: { padding: "4px 12px", fontSize: 12 } }, "Refresh"),
    ),
    e("div", { className: "canvas" },
      e(ReactFlowProvider, null,
        e(ReactFlow, {
          nodes, edges, onNodesChange, onEdgesChange, onNodeClick,
          fitView: true, panOnScroll: true, minZoom: 0.1, maxZoom: 3,
        },
          e(Background, null),
          e(MiniMap, { pannable: true, zoomable: true }),
          e(Controls, null),
        ),
      ),
    ),
    e("div", { className: "panel" },
      !selected
        ? e("div", { className: "empty" }, "Click any source or sink to inspect and add notes.")
        : e(React.Fragment, null,
            e("h2", null, selected.label || selected.id),
            e("div", { className: "meta" }, JSON.stringify(selected, null, 2)),
            e("h2", null, "Notes"),
            notes.length === 0
              ? e("div", { className: "empty" }, "No notes yet.")
              : notes.map((n) => e("div", { key: n.rowid, className: "note" },
                  e("div", null,
                    e("span", { className: "layer" }, n.layer || "human"),
                    " ",
                    e("span", { className: "ts" }, n.ts),
                    e("span", { className: "pin", onClick: () => deleteNote(n.rowid), title: "delete" }, "×"),
                  ),
                  e("div", null, n.content),
                )),
            e("textarea", {
              value: draft,
              onChange: (ev) => setDraft(ev.target.value),
              placeholder: "Add a note (Ctrl+Enter to save)…",
              onKeyDown: (ev) => { if (ev.ctrlKey && ev.key === "Enter") saveNote(); },
            }),
            e("div", { style: { marginTop: 8, display: "flex", gap: 8 } },
              e("button", { onClick: saveNote }, "Save note"),
              e("button", { className: "secondary", onClick: () => setDraft("") }, "Clear"),
            ),
          ),
    ),
  );
}

createRoot(document.getElementById("root")).render(e(App));
