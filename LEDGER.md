# egg-verify failure ledger

public commitment, kept here: every call attempt that reaches a paid egg-verify
route is recorded with its outcome, failure reason, the usdc actually charged,
and the compute cost absorbed by the operator on failures. billing figures and
uncharged compute sit side by side.

## where it lives

- live json: `https://egg-verify.onrender.com/ledger` (optional `?limit=n`)
- human page: `https://egg-verify.onrender.com/ledger.html`
- chain check: `https://egg-verify.onrender.com/ledger/verify`

## scheme (ledger-v0.1)

`ledger.log.jsonl`, one json object per line, next to `server.js` (see
`ledger.js`). each entry carries:

- `seq`, `ts`, `endpoint`, `outcome` ("success" | "failed")
- `failure_reason`: one of `invalid_input`, `bad_url`, `fetch_failed`,
  `too_little_text`, `internal` (null on success)
- `amount_charged_usdc`: list price on success, `0` on failure
- `uncharged_compute_usd`: estimated absorbed compute, `0` on success
- `compute_model`: pinned model id so revisions stay comparable
- `tx`, `payer`: settlement header when present (null on failure)
- `prev_hash`: sha256 of the previous entry
- `entry_hash`: sha256(prev_hash + "|" + canonical json of the entry)

the first entry is `genesis` and documents the scheme itself. unpaid
(402) calls never reach a route handler, so they are not ledger entries:
they are payment negotiations, not call attempts, and they cost nothing.

## the uncharged compute estimate

model `uncharged-compute-v0.1`: a failed call still burns real work on the
instance (request parsing, validation, usually an outbound fetch with a 20s
timeout, text extraction, the payment round trips). the model books
**$0.0001 per failed attempt** — roughly 10,000 failed attempts per $1 of
absorbed compute, on the order of a $7/mo starter tier amortized over
traffic.

this is a stated estimate, not metered billing, and the page says so. it
exists to make the cost of "failed calls never charge" visible instead of
hand-waved. future revisions pin a new model id so old entries stay
comparable.

## honesty notes

1. **ephemeral storage.** render free tier disk is not durable. entries
   survive until the instance sleeps (~15 min idle) or redeploys, then they
   are gone. the ledger page footer says this. nothing here fakes durability
   it does not have. future step: periodic git-committed snapshots of
   `ledger.log.jsonl` (not built yet; would need a push credential the
   operator has not approved from the instance).
2. **self-reported.** the operator writes the ledger about its own service.
   the hash chain proves the record was not edited after the fact, not that
   the recorded facts are complete. a missing entry is still a missing
   entry — the chain only detects tampering with what is there.
3. **unaudited compute model.** the $0.0001 figure is our own estimate.
   auditors are welcome to propose a better one.

## verifying

```sh
node -e "const l = require('./ledger.js'); console.log(l.verifyChain());"
```

or hit `/ledger/verify` on the live service. recompute
sha256(prev_hash + "|" + canonical entry) down the chain yourself against
`/ledger` if you want the fully trustless check.
