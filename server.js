// egg-verify: x402-paywalled claim verification API.
// POST /verify {claim, url} -> SUPPORTED / REFUTED / UNCLEAR with quoted page evidence.
// Payment: $0.05 USDC on Base (exact scheme), verified+settled via the official
// @x402/express middleware and a public facilitator. No hand-rolled crypto.
const express = require("express");
const dns = require("dns").promises;
const net = require("net");
const fs = require("fs");
const path = require("path");
const { paymentMiddleware, x402ResourceServer } = require("@x402/express");
const { ExactEvmScheme } = require("@x402/evm/exact/server");
const { HTTPFacilitatorClient } = require("@x402/core/server");

const PORT = Number(process.env.PORT || 4021);
const NETWORK = process.env.X402_NETWORK || "eip155:84532"; // Base Sepolia testnet default
const FACILITATOR_URL =
  process.env.X402_FACILITATOR_URL || "https://x402.org/facilitator";
const PAY_TO =
  process.env.X402_PAY_TO || "0x146ECb985fc03640F44aD0c8d9aB16eb233d1A83";
const PRICE = "$0.05";
const SALES_LOG = process.env.VERCEL ? "/tmp/sales.log.jsonl" : path.join(__dirname, "sales.log.jsonl");
const UA =
  "Mozilla/5.0 (compatible; egg-verify/0.1; x402 verification bot; +https://x402.org)";

// ---------- SSRF guard ----------
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return (
      a === 10 || a === 127 || a === 0 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254)
    );
  }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    return l === "::1" || l.startsWith("fe80:") || l.startsWith("fc") || l.startsWith("fd");
  }
  return true; // unknown -> treat as unsafe
}

async function assertPublicUrl(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    throw new Error("invalid URL");
  }
  if (!["http:", "https:"].includes(u.protocol)) throw new Error("only http/https URLs allowed");
  if (net.isIP(u.hostname) && isPrivateIp(u.hostname)) throw new Error("private IP not allowed");
  let addrs;
  try {
    addrs = await dns.lookup(u.hostname, { all: true });
  } catch {
    throw new Error("hostname did not resolve");
  }
  if (addrs.some((a) => isPrivateIp(a.address))) throw new Error("hostname resolves to private IP");
  return u;
}

const { PDFParse } = require("pdf-parse");

// ---------- page fetch + text extraction ----------
async function fetchPageText(u) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 20000);
  let res;
  try {
    res = await fetch(u.toString(), {
      signal: ctrl.signal,
      redirect: "follow",
      headers: { "User-Agent": UA, Accept: "text/html,application/xhtml+xml,text/plain,application/pdf" },
    });
  } finally {
    clearTimeout(t);
  }
  if (!res.ok) throw new Error(`page fetch failed: HTTP ${res.status}`);
  const ct = res.headers.get("content-type") || "";
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > 4_000_000) throw new Error("document too large (>4MB)");
  if (/pdf/.test(ct) || buf.subarray(0, 4).toString() === "%PDF") {
    // PDFs (e.g. organizer fee schedules) — extract text directly
    const parser = new PDFParse({ data: buf });
    try {
      const result = await parser.getText();
      const text = result.text || (result.pages || []).map((p) => p.text).join(" ") || "";
      const clean = String(text).replace(/\s+/g, " ").trim();
      if (clean.length < 50) throw new Error("PDF yielded no readable text");
      return clean;
    } finally {
      await parser.destroy().catch(() => {});
    }
  }
  if (!/text|html|json|xml/.test(ct)) throw new Error(`unsupported content type: ${ct}`);
  return buf.toString("utf8");
}

function extractText(html) {
  let t = html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, " ")
    .replace(/<[^>]+>/g, " ");
  t = t
    .replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'");
  return t.replace(/\s+/g, " ").trim();
}

function splitSentences(text) {
  return text.split(/(?<=[.!?])\s+/).map((s) => s.trim()).filter((s) => s.length > 25 && s.length < 600);
}

// ---------- honest heuristic judge ----------
const STOP = new Set(
  "a,an,the,is,are,was,were,be,been,being,of,to,in,on,for,with,by,at,from,as,and,or,not,no,do,does,did,have,has,had,this,that,these,those,it,its,they,their,he,she,we,you,i,what,which,who,when,where,why,how,can,will,would,should,could,may,might,must,than,then,so,such,also,only,just,very,more,most,all,any,each,other,some,into,over,after,before,between,through,during,about,against,per".split(",")
);

function keywords(claim) {
  return [...new Set(
    claim.toLowerCase().replace(/[^a-z0-9\s]/g, " ").split(/\s+/)
      .filter((w) => w.length > 2 && !STOP.has(w))
  )];
}

const REFUTE_CUES = ["not ", "no ", "never", "n't ", "false", "incorrect", "wrong", "myth", "debunked", "denies", "denied", "refutes", "contrary", "disproven", "hoax", "no evidence"];
const PRICE_RE = /\$\s?\d[\d,]*/;
const FEE_WORDS_RE = /\b(fee|fees|pricing|price|cost|costs|charged|payment)\b/i;
const ASSERTS_FREE_RE = /\bfree\b|\bno\s+(fee|charge|cost)s?\b|\bwithout\s+(fee|charge|cost)s?\b|\bzero\s+cost\b/i;
const NEGATION_RE = /\b(not|never|no|n't|cannot|can't|won't|don't|doesn't)\b/i;

function judge(claim, text) {
  const kw = keywords(claim);
  if (kw.length === 0) {
    return { verdict: "UNCLEAR", confidence: "low", evidence: [], note: "claim had no usable key terms" };
  }
  const scored = [];
  for (const s of splitSentences(text)) {
    const low = s.toLowerCase();
    const hits = kw.filter((k) => low.includes(k)).length;
    if (hits >= 2) scored.push({ s, hits });
  }
  scored.sort((a, b) => b.hits - a.hits);
  const top = scored.slice(0, 3); // verbatim substrings of the page; never invented
  if (top.length === 0) {
    return { verdict: "UNCLEAR", confidence: "low", evidence: [], note: "no page content matched the claim's key terms" };
  }
  const joined = top.map((t) => t.s.toLowerCase()).join(" ");
  const refuteHits = REFUTE_CUES.filter((c) => joined.includes(c)).length;
  const best = top[0].hits;

  // Contradiction: claim asserts freeness, but the page itself lists prices/fees.
  // The page's own pricing refutes the claim — this is a sound, non-invented verdict.
  if (ASSERTS_FREE_RE.test(claim) && (PRICE_RE.test(joined) || FEE_WORDS_RE.test(joined))) {
    const priceQuotes = top.filter((t) => PRICE_RE.test(t.s) || FEE_WORDS_RE.test(t.s)).map((t) => t.s);
    return {
      verdict: "REFUTED",
      confidence: "medium",
      evidence: (priceQuotes.length ? priceQuotes : top.map((t) => t.s)),
      note: "claim asserts no cost, but the page lists prices/fees",
    };
  }

  if (refuteHits >= 2 && best >= 3) {
    return { verdict: "REFUTED", confidence: "medium", evidence: top.map((t) => t.s), note: "refutation language found near claim terms" };
  }

  // Negated claims are unreliable for keyword-overlap heuristics: a SUPPORTED
  // verdict here would often be exactly backwards. Stay honest -> UNCLEAR.
  if (NEGATION_RE.test(claim)) {
    return { verdict: "UNCLEAR", confidence: "low", evidence: top.map((t) => t.s), note: "claim contains negation the heuristic cannot resolve reliably; inspect the quoted evidence manually" };
  }

  if (best >= 4 && kw.length >= 4) {
    return { verdict: "SUPPORTED", confidence: "medium", evidence: top.map((t) => t.s), note: "strong term overlap with page content" };
  }
  return { verdict: "UNCLEAR", confidence: "low", evidence: top.map((t) => t.s), note: "only partial matches; heuristic-v0.1 is conservative — verify manually for important decisions" };
}

// ---------- app ----------
const app = express();

const facilitatorClient = new HTTPFacilitatorClient({ url: FACILITATOR_URL });
const resourceServer = new x402ResourceServer(facilitatorClient).register(
  NETWORK,
  new ExactEvmScheme()
);

app.use(express.json({ limit: "64kb" }));

app.use(
  paymentMiddleware(
    {
      "POST /verify": {
        accepts: {
          scheme: "exact",
          price: PRICE,
          network: NETWORK,
          payTo: PAY_TO,
          maxTimeoutSeconds: 300,
        },
        description:
          "Verify a factual claim against a public URL. Returns SUPPORTED / REFUTED / UNCLEAR with quoted page evidence.",
        mimeType: "application/json",
        extensions: {
          // x402 Bazaar discovery: facilitators catalog this endpoint from payment
          // payloads so agents can find it via /discovery/resources. no form, no account.
          bazaar: {
            discoverable: true,
            inputSchema: {
              type: "object",
              properties: {
                claim: {
                  type: "string",
                  description: "The factual claim to verify (max 500 characters)",
                },
                url: {
                  type: "string",
                  description: "Public http(s) URL to check the claim against. HTML and PDF supported.",
                },
              },
              required: ["claim", "url"],
            },
            outputSchema: {
              type: "object",
              properties: {
                verdict: { type: "string", description: "SUPPORTED, REFUTED, or UNCLEAR" },
                confidence: { type: "string", description: "low | medium | high" },
                evidence: {
                  type: "array",
                  items: { type: "string" },
                  description: "Verbatim quotes from the checked page",
                },
                method: { type: "string", description: "heuristic-v0.1 keyword-overlap check" },
              },
            },
          },
        },
      },
    },
    resourceServer
  )
);

app.get("/", (req, res) => {
  res.json({
    name: "egg-verify",
    protocol: "x402 v2",
    description:
      "Pay-per-call claim verification. POST a factual claim plus a public URL; get back SUPPORTED / REFUTED / UNCLEAR with quoted evidence from the page.",
    price: PRICE,
    currency: "USDC",
    network: NETWORK,
    payTo: PAY_TO,
    facilitator: FACILITATOR_URL,
    endpoints: {
      "GET /": "this service card (free)",
      "GET /health": "liveness check (free)",
      "POST /verify": `${PRICE} USDC per call. body: {"claim": "string (max 500 chars)", "url": "https://..."}`,
    },
    how_to_pay: [
      "1. POST /verify without payment -> HTTP 402 with payment requirements in the PAYMENT-REQUIRED header",
      "2. sign an EIP-3009 authorization for the required amount with your wallet",
      "3. retry POST /verify with the PAYMENT-SIGNATURE header",
      "4. receive HTTP 200 with the verification JSON and a PAYMENT-RESPONSE settlement header",
    ],
    buyer_sdks: ["npm: @x402/core @x402/evm @x402/fetch  (wrapFetch handles the 402 flow automatically)"],
    notes: [
      "no accounts, no API keys, no KYC needed to pay",
      "payment settles only after a successful verification response",
      "verdicts are an automated heuristic (method: heuristic-v0.1); evidence quotes are verbatim page excerpts",
    ],
  });
});

app.get("/health", (req, res) => {
  res.json({ status: "ok", service: "egg-verify", network: NETWORK, price: PRICE, payTo: PAY_TO, facilitator: FACILITATOR_URL, time: new Date().toISOString() });
});

app.post("/verify", async (req, res) => {
  // NOTE: the x402 middleware only settles payment after this handler responds
  // successfully, so buyers are never charged for failed verifications.
  try {
    const { claim, url } = req.body || {};
    if (typeof claim !== "string" || !claim.trim() || claim.length > 500) {
      return res.status(400).json({ error: "claim must be a non-empty string (max 500 chars)" });
    }
    if (typeof url !== "string" || !url.trim() || url.length > 2048) {
      return res.status(400).json({ error: "url must be a string (max 2048 chars)" });
    }
    const u = await assertPublicUrl(url.trim());
    const html = await fetchPageText(u);
    const text = extractText(html);
    if (text.length < 200) {
      return res.status(422).json({ error: "page yielded too little readable text to judge", url: u.toString() });
    }
    const { verdict, confidence, evidence, note } = judge(claim.trim(), text);

    let settlement = null;
    try {
      const h = res.getHeader("PAYMENT-RESPONSE");
      if (h) settlement = JSON.parse(Buffer.from(String(h), "base64").toString("utf8"));
    } catch { /* header not present yet at this point in some flows */ }
    try {
      fs.appendFileSync(
        SALES_LOG,
        JSON.stringify({ ts: new Date().toISOString(), network: NETWORK, price: PRICE, payTo: PAY_TO, claim: claim.trim().slice(0, 120), url: u.toString(), verdict, tx: settlement?.transaction || null, payer: settlement?.payer || null }) + "\n"
      );
    } catch { /* logging must never break the response */ }

    res.json({
      claim: claim.trim(),
      url: u.toString(),
      verdict,
      confidence,
      evidence,
      method: "heuristic-v0.1",
      checked_at: new Date().toISOString(),
      note,
      disclaimer: "automated heuristic verdict, not financial or legal advice; verify manually before acting on important decisions",
    });
  } catch (e) {
    res.status(422).json({ error: String((e && e.message) || e), method: "heuristic-v0.1" });
  }
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`egg-verify listening on :${PORT} | network=${NETWORK} | price=${PRICE} | payTo=${PAY_TO} | facilitator=${FACILITATOR_URL}`);
  });
}

// exported for serverless deployment (Vercel) and offline unit-testing (no payment involved)
module.exports = { app, judge, extractText, splitSentences, keywords, assertPublicUrl, fetchPageText };
