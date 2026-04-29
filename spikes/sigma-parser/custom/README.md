# `custom/` — hand-rolled OLT-only parser POC

Story 1.2 spike. Demonstrates that the OLT subset of SIGMA-HQ can be
matched by a naive ~280-line Go parser, and serves as the LOC-honest
input to AC7's fallback custom-parser estimate.

## What this POC covers

- Loading the OLT-IMPACT-005 rule via `gopkg.in/yaml.v3`.
- Lint-checking the rule ID against
  `^OLT-(EXEC|NET|FILE|PRIV|IMPACT|RECON|PERSIST|EXFIL|CRED|LATERAL)-[0-9]{3}$`
  per architecture.md:470.
- Splitting `field|modifier` keys and applying the five modifiers the
  POC supports: `contains`, `startswith`, `endswith`, `re`, `cidr`.
- Walking a flat AND condition (`A and B and C`) and matching every
  named search-identifier block.

## What this POC deliberately does not cover

- OR / NOT operators, parentheses, `1 of`, `all of`, sub-condition
  references — full SIGMA-HQ condition grammar is the main argument
  for the wrap path, not against it.
- Aggregations and `Near()` operators (rare in practice; sigmalite
  itself does not implement them).
- Modifier coverage beyond the five above — the full list is
  `contains|all|startswith|endswith|windash|base64|base64offset|re|cidr|expand`.
- Field-resolver indirection. The POC reads flat top-level keys; the
  k8s.* / streaming-event split that the wrap POC demonstrates would
  need to be re-implemented here.

## Cost projection (input to AC7)

A production custom parser that genuinely replaces sigmalite would
need at minimum:

- Full condition grammar (10x more lines than the AND-only POC).
- All ten standard modifiers (each adds 5-15 lines plus tests).
- Field-resolver indirection.
- A SIGMA-HQ regression test corpus (community rules must remain
  parseable per the strict-superset claim).

Realistic estimate: 1500-2500 lines plus 1500 lines of tests, two to
four engineering weeks. Refer to ADR-2026-04-28-01 for the calendar
trade-off this implies for Story 1.15.

## Running it

From this directory:

```
go run .
```

Expected output:

```
[custom] parsed rule id=OLT-IMPACT-005 title="Cryptominer process pattern in unprivileged Pod" attack=[T1496] severity=75
[custom] positive               want=true got=true PASS
[custom] negative_namespace     want=false got=false PASS
[custom] negative_process       want=false got=false PASS
[custom] fixtures: 3/3 passed
```

A non-PASS exits non-zero.
