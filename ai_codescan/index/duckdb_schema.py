"""DuckDB schema for the ai-codescan project DB."""

from __future__ import annotations

import duckdb

PHASE1_TABLES_DDL = """
CREATE TABLE IF NOT EXISTS files (
  path VARCHAR PRIMARY KEY,
  sha256 VARCHAR NOT NULL,
  lang VARCHAR,
  project_id VARCHAR,
  size BIGINT
);

CREATE TABLE IF NOT EXISTS symbols (
  id VARCHAR PRIMARY KEY,
  sym VARCHAR NOT NULL,
  kind VARCHAR NOT NULL,
  file VARCHAR NOT NULL,
  range_start INTEGER NOT NULL,
  range_end INTEGER NOT NULL,
  type VARCHAR,
  display_name VARCHAR
);

CREATE TABLE IF NOT EXISTS xrefs (
  caller_id VARCHAR,
  callee_id VARCHAR,
  kind VARCHAR NOT NULL,
  file VARCHAR,
  line INTEGER
);

CREATE TABLE IF NOT EXISTS taint_sources (
  tid VARCHAR PRIMARY KEY,
  symbol_id VARCHAR,
  class VARCHAR,
  key VARCHAR,
  evidence_loc VARCHAR
);

CREATE TABLE IF NOT EXISTS taint_sinks (
  sid VARCHAR PRIMARY KEY,
  symbol_id VARCHAR,
  class VARCHAR,
  lib VARCHAR,
  parameterization VARCHAR,
  tainted_slots_json VARCHAR
);

CREATE TABLE IF NOT EXISTS flows (
  fid VARCHAR PRIMARY KEY,
  tid VARCHAR,
  sid VARCHAR,
  cwe VARCHAR,
  engine VARCHAR,
  steps_json VARCHAR,
  sarif_ref VARCHAR,
  confidence VARCHAR
);

-- Sidecar table recording how each flow was produced. Currently only
-- distinguishes data-flow-engine flows from Joern's co-location fallback so
-- the scorer can demote co-location candidates (Recall-First Invariant 6).
-- A missing row means flow_type = 'dataflow' (the default).
CREATE TABLE IF NOT EXISTS flow_metadata (
  fid VARCHAR PRIMARY KEY,
  flow_type VARCHAR DEFAULT 'dataflow'
);

CREATE TABLE IF NOT EXISTS candidate_scores (
  candidate_id VARCHAR PRIMARY KEY,
  flow_id VARCHAR,
  stream VARCHAR,
  score DOUBLE,
  label VARCHAR,
  processing_bucket VARCHAR,
  factors_json VARCHAR,
  scorer VARCHAR,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Phase 3 model-extension feedback loop: tracks whether a proposal is still
-- pending, has been applied (rule rendered), or has been rejected. Survives
-- runs so the user sees a stable status across reanalyses.
CREATE TABLE IF NOT EXISTS proposal_decisions (
  proposal_id VARCHAR PRIMARY KEY,
  decision VARCHAR,         -- pending | applied | rejected
  engine VARCHAR,
  applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  eval_positive VARCHAR,
  eval_negative VARCHAR,
  applied_path VARCHAR
);

CREATE TABLE IF NOT EXISTS review_verdicts (
  nomination_id VARCHAR PRIMARY KEY,
  finding_id VARCHAR,
  flow_id VARCHAR,
  candidate_id VARCHAR,
  verdict VARCHAR,
  status VARCHAR,
  confidence VARCHAR,
  cwe VARCHAR,
  title VARCHAR,
  evidence_json VARCHAR,
  reviewer VARCHAR,
  source_path VARCHAR,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notes (
  symbol_id VARCHAR,
  layer VARCHAR,
  author VARCHAR,
  content VARCHAR,
  pinned BOOLEAN DEFAULT FALSE,
  ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS entrypoints (
  symbol_id VARCHAR,
  kind VARCHAR,
  signature VARCHAR,
  file VARCHAR,
  line INTEGER
);
"""

PHASE2_RESERVED_DDL = """
CREATE TABLE IF NOT EXISTS storage_locations (
  storage_id VARCHAR PRIMARY KEY,
  kind VARCHAR,
  schema_evidence VARCHAR
);

CREATE TABLE IF NOT EXISTS storage_writes (
  storage_id VARCHAR,
  flow_id VARCHAR,
  source_tid VARCHAR,
  symbol_id VARCHAR,
  call_shape_json VARCHAR
);

CREATE TABLE IF NOT EXISTS storage_reads (
  storage_id VARCHAR,
  symbol_id VARCHAR,
  result_binding_id VARCHAR
);

CREATE TABLE IF NOT EXISTS storage_taint (
  storage_id VARCHAR,
  derived_tid VARCHAR,
  contributing_tids_json VARCHAR,
  confidence VARCHAR
);
"""

VIEWS_DDL = """
CREATE OR REPLACE VIEW v_sources_to_sinks AS
SELECT
  ts.symbol_id AS source_symbol_id,
  ts2.symbol_id AS sink_symbol_id,
  list(f.fid)   AS fids,
  list(f.cwe)   AS cwes
FROM flows f
JOIN taint_sources ts  ON ts.tid = f.tid
JOIN taint_sinks   ts2 ON ts2.sid = f.sid
GROUP BY ts.symbol_id, ts2.symbol_id;

CREATE OR REPLACE VIEW v_sinks_from_sources AS
SELECT
  ts2.symbol_id AS sink_symbol_id,
  ts.symbol_id  AS source_symbol_id,
  list(f.fid)   AS fids,
  list(f.cwe)   AS cwes
FROM flows f
JOIN taint_sources ts  ON ts.tid = f.tid
JOIN taint_sinks   ts2 ON ts2.sid = f.sid
GROUP BY ts2.symbol_id, ts.symbol_id;
"""


def apply_schema(conn: duckdb.DuckDBPyConnection) -> None:
    """Apply Phase 1 + Phase 2-reserved tables and the navigation views."""
    conn.execute(PHASE1_TABLES_DDL)
    conn.execute(PHASE2_RESERVED_DDL)
    conn.execute(VIEWS_DDL)
