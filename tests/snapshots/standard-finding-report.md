# SQL injection in account lookup

## Summary

The account lookup concatenates an untrusted identifier.

## Classification

- Finding ID: `F-101`
- Severity: `critical`
- CWE: `CWE-89`
- Vulnerability class: `sqli`
- Confidence: `high`
- Validation status: `verified`
- Exploitability: `unknown`
- Review verdict: `true-positive`
- Reviewer: `deep_analyzer`

## Affected Location

- src/accounts.ts:42

## Impact

An attacker can change the query and read another account.

## Evidence

`accountId` reaches `db.query` without a bound parameter.

## Scanner Evidence

No scanner evidence was recorded.

## Validation

The observation-only test caused a SQL parser error.

## Reproduction

No reproduction steps were recorded.

## Proof of Concept

Not included because this report uses the recorded validation evidence.

## Prerequisites

No unmet prerequisites were recorded.

## Remediation

Use a bound parameter for `accountId`.

## Open Questions

Does a database role limit access to other tenants?

## References

- Nomination ID: `N-101`
- Flow ID: `flow-101`
