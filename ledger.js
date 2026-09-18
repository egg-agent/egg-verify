// egg-verify failure ledger.
// Append-only, hash-chained record of every call attempt that reaches a paid
// route handler. This is the public evidence behind the claim "failed calls
// never charge": each entry binds the outcome to the hash of the previous
// entry, so any edit or deletion breaks the chain and is detectable by anyone
// at GET /ledger/verify.
//
// entry = {
//   seq, ts, endpoint, outcome: "success"|"failed",
//   failure_reason: null | string (stable machine code, see REASONS below),
//   amount_charged_usdc: number (price on success, 0.0 on failure),
//   uncharged_compute_usd: number (estimated absorbed cost; 0 on success),
//   tx, payer, prev_hash, entry_hash
// }
//
// entry_hash = sha256(canonical(prev_hash + "|" + JSON.stringify(entry sans hashes)))
//
// uncharged compute model v0.1 (estimate, not audited):
// a failed call still burns real work on this instance: request parsing,
// validation, usually an outbound fetch with a 20s timeout, text extraction,
// and the 402/payment round trips. the model charges $0.0001 per failed
// attempt, i.e. ~10k failed attempts ≈ $1.00 of absorbed compute. that is on
// the order of a $7/mo starter tier amortized over traffic — a stated estimate,
// not a metered cost. success entries carry 0 because the buyer's payment
// covers them. the model version is pinned on each entry so future revisions
// stay comparable.
//
// storage: JSONL, one entry per line, ledger.log.jsonl next to server.js.
// on render free tier the disk is ephemeral (see LEDGER.md): entries survive
// only until the instance sleeps or redeploys. nothing here fakes durability
// it does not have.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const LEDGER_FILE =
  process.env.VERCEL ? "/tmp/ledger.log.jsonl" : path.join(__dirname, "ledger.log.jsonl");

const SCHEME_VERSION = "ledger-v0.1";
const COMPUTE_MODEL = "uncharged-compute-v0.1";
const FAILURE_COST_USD = 0.0001; // per failed attempt, see model note above

const GENESIS_PREV = "0".repeat(64);

// stable failure reason codes. keep lowercase, no spaces.
const REASONS = {
  INVALID_INPUT: "invalid_input", // 400: malformed brief/claim/urls
  BAD_URL: "bad_url", // SSRF guard / unresolvable / private ip
  FETCH_FAILED: "fetch_failed", // upstream page/pdf fetch error or timeout
  TOO_LITTLE_TEXT: "too_little_text", // 422: page readable but unusable
  INTERNAL: "internal", // 500: unexpected server error
};

function canonical(entry) {
  // entry without hashes, stable key order
  return JSON.stringify({
    scheme: SCHEME_VERSION,
    seq: entry.seq,
    ts: entry.ts,
    endpoint: entry.endpoint,
    outcome: entry.outcome,
    failure_reason: entry.failure_reason,
    amount_charged_usdc: entry.amount_charged_usdc,
    uncharged_compute_usd: entry.uncharged_compute_usd,
    compute_model: COMPUTE_MODEL,
    tx: entry.tx || null,
    payer: entry.payer || null,
  });
}

function hashEntry(prevHash, entryWithoutHashes) {
  return crypto
    .createHash("sha256")
    .update(prevHash + "|" + canonical(entryWithoutHashes), "utf8")
    .digest("hex");
}

function genesisEntry() {
  const e = {
    scheme: SCHEME_VERSION,
    seq: 0,
    ts: new Date().toISOString(),
    type: "genesis",
    endpoint: null,
    outcome: "genesis",
    failure_reason: null,
    amount_charged_usdc: 0,
    uncharged_compute_usd: 0,
    compute_model: COMPUTE_MODEL,
    tx: null,
    payer: null,
    note:
      "genesis. this ledger records every attempt that reaches a paid egg-verify " +
      "route. failed calls never charge; the absorbed compute cost is estimated " +
      "at $0.0001 per failed attempt (" + COMPUTE_MODEL + "). each entry " +
      "chains to the previous via sha256, so tampering is detectable. storage " +
      "is a local jsonl file: entries are lost if the instance disk is recycled, " +
      "see LEDGER.md for the honesty notes.",
  };
  e.prev_hash = GENESIS_PREV;
  e.entry_hash = hashEntry(GENESIS_PREV, e);
  return e;
}

function readEntries() {
  try {
    const raw = fs.readFileSync(LEDGER_FILE, "utf8");
    return raw
      .split("\n")
      .filter((l) => l.trim())
      .map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}

// append a new attempt. fields: endpoint, outcome, failureReason, amountChargedUsdc, tx, payer.
// returns the written entry. logging must never throw into the request path.
function recordAttempt(fields) {
  const prev = (() => {
    const entries = readEntries();
    return entries.length ? entries[entries.length - 1] : null;
  })();

  let e;
  if (!prev) {
    e = genesisEntry();
    try {
      fs.appendFileSync(LEDGER_FILE, JSON.stringify(e) + "\n");
    } catch { /* best effort */ }
  }
  const tip = e || prev;
  const next = {
    scheme: SCHEME_VERSION,
    seq: tip.seq + 1,
    ts: new Date().toISOString(),
    endpoint: fields.endpoint,
    outcome: fields.outcome, // "success" | "failed"
    failure_reason: fields.outcome === "failed" ? (fields.failureReason || REASONS.INTERNAL) : null,
    amount_charged_usdc: fields.amountChargedUsdc || 0,
    uncharged_compute_usd:
      fields.outcome === "failed" ? FAILURE_COST_USD : 0,
    compute_model: COMPUTE_MODEL,
    tx: fields.tx || null,
    payer: fields.payer || null,
  };
  next.prev_hash = tip.entry_hash;
  next.entry_hash = hashEntry(tip.entry_hash, next);
  try {
    fs.appendFileSync(LEDGER_FILE, JSON.stringify(next) + "\n");
  } catch { /* best effort */ }
  return next;
}

// recompute the whole chain. returns {ok, entries, broken_at, broken_hash}.
function verifyChain() {
  const entries = readEntries();
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    const expectedPrev = i === 0 ? GENESIS_PREV : entries[i - 1].entry_hash;
    if (e.prev_hash !== expectedPrev) {
      return { ok: false, entries: entries.length, broken_at: e.seq, broken_reason: "prev_hash mismatch" };
    }
    const recomputed = hashEntry(e.prev_hash, e);
    if (recomputed !== e.entry_hash) {
      return { ok: false, entries: entries.length, broken_at: e.seq, broken_reason: "entry_hash mismatch" };
    }
    if (i > 0 && e.seq !== entries[i - 1].seq + 1) {
      return { ok: false, entries: entries.length, broken_at: e.seq, broken_reason: "sequence gap" };
    }
  }
  return { ok: true, entries: entries.length, broken_at: null, broken_reason: null };
}

function summary(entries) {
  const attempts = entries.filter((e) => e.outcome === "success" || e.outcome === "failed");
  const successes = attempts.filter((e) => e.outcome === "success");
  const failures = attempts.filter((e) => e.outcome === "failed");
  const byReason = {};
  for (const f of failures) byReason[f.failure_reason] = (byReason[f.failure_reason] || 0) + 1;
  const settledUsdc = round(successes.reduce((s, e) => s + e.amount_charged_usdc, 0));
  const unchargedUsd = round(failures.reduce((s, e) => s + e.uncharged_compute_usd, 0));
  return {
    total_attempts: attempts.length,
    successes: successes.length,
    failures: failures.length,
    failures_by_reason: byReason,
    settled_usdc: settledUsdc,
    uncharged_compute_usd: unchargedUsd,
    compute_model: COMPUTE_MODEL,
  };
}

function round(n) {
  return Math.round(n * 1e6) / 1e6;
}

module.exports = {
  LEDGER_FILE,
  SCHEME_VERSION,
  COMPUTE_MODEL,
  REASONS,
  recordAttempt,
  verifyChain,
  readEntries,
  summary,
  genesisEntry,
};
