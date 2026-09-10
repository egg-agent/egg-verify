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
const SCOUT_PRICE = "$0.50";
const DEEPDIVE_PRICE = "$2.00";
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
    // keep block-level boundaries so adjacent blocks don't merge into one "sentence"
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(p|div|li|h[1-6]|tr|td|section|article|blockquote|header|footer|nav)>/gi, "\n")
    .replace(/<[^>]+>/g, " ");
  t = t
    .replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'");
  return t.replace(/[ \t]+/g, " ").replace(/\n+/g, "\n").trim();
}

function splitSentences(text) {
  return text.split(/(?<=[.!?])\s+|\n+/).map((s) => s.trim()).filter((s) => s.length > 25 && s.length < 600);
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

// ---------- hire-a-subagent: extractive research (no LLM, no API keys) ----------
function validateTaskBody(body, maxUrls) {
  const { brief, urls } = body || {};
  if (typeof brief !== "string" || !brief.trim() || brief.length > 500) {
    return { error: "brief must be a non-empty string (max 500 chars)" };
  }
  if (!Array.isArray(urls) || urls.length === 0 || urls.length > maxUrls) {
    return { error: `urls must be an array of 1-${maxUrls} public URLs` };
  }
  for (const u of urls) {
    if (typeof u !== "string" || !u.trim() || u.length > 2048) {
      return { error: "each url must be a string (max 2048 chars)" };
    }
  }
  return { brief: brief.trim(), urls: urls.map((u) => u.trim()) };
}

// fetch every source in parallel inside a hard time budget; never throw
async function fetchSources(urls, budgetMs) {
  return Promise.all(
    urls.map(async (raw) => {
      const job = (async () => {
        try {
          const u = await assertPublicUrl(raw);
          const html = await fetchPageText(u);
          const text = extractText(html);
          if (text.length < 200)
            return { url: u.toString(), status: "error", error: "too little readable text" };
          return { url: u.toString(), status: "ok", text: text.slice(0, 60000) };
        } catch (e) {
          return { url: String(raw), status: "error", error: String((e && e.message) || e).slice(0, 200) };
        }
      })();
      const timer = new Promise((res) =>
        setTimeout(() => res({ url: String(raw), status: "error", error: "fetch exceeded time budget" }), budgetMs)
      );
      return Promise.race([job, timer]);
    })
  );
}

// rank sentences by brief-keyword overlap; verbatim, never invented
function rankSentences(text, kw, minHits) {
  const out = [];
  for (const s of splitSentences(text)) {
    const low = s.toLowerCase();
    const hits = kw.length ? kw.filter((k) => low.includes(k)).length : 0;
    if (hits >= (minHits || 1)) out.push({ s, hits });
  }
  out.sort((a, b) => b.hits - a.hits || a.s.length - b.s.length);
  return out;
}

function firstSentences(text, n) {
  return splitSentences(text).slice(0, n).map((s) => s);
}

// cross-source deduped top sentences for the summary/synthesis
function topAcrossSources(okSources, kw, n) {
  const pool = [];
  for (const s of okSources) {
    const ranked = kw.length ? rankSentences(s.text, kw) : firstSentences(s.text, 5).map((x) => ({ s: x, hits: 0 }));
    for (const r of ranked) pool.push({ ...r, url: s.url });
  }
  pool.sort((a, b) => b.hits - a.hits);
  const seen = new Set();
  const out = [];
  for (const r of pool) {
    const key = r.s.slice(0, 80).toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(r.s);
    if (out.length >= n) break;
  }
  return out;
}

function logSale(res, fields) {
  try {
    let settlement = null;
    try {
      const h = res.getHeader("PAYMENT-RESPONSE");
      if (h) settlement = JSON.parse(Buffer.from(String(h), "base64").toString("utf8"));
    } catch { /* header not present yet in some flows */ }
    fs.appendFileSync(
      SALES_LOG,
      JSON.stringify({
        ts: new Date().toISOString(), network: NETWORK, payTo: PAY_TO,
        tx: settlement?.transaction || null, payer: settlement?.payer || null,
        ...fields,
      }) + "\n"
    );
  } catch { /* logging must never break the response */ }
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
      "POST /scout": {
        accepts: {
          scheme: "exact",
          price: SCOUT_PRICE,
          network: NETWORK,
          payTo: PAY_TO,
          maxTimeoutSeconds: 300,
        },
        description:
          "Quick research scout: fetch up to 3 public URLs server-side and return an extractive summary keyed to your brief, with per-source key points and verbatim quotes.",
        mimeType: "application/json",
        extensions: {
          bazaar: {
            discoverable: true,
            inputSchema: {
              type: "object",
              properties: {
                brief: {
                  type: "string",
                  description: "The research question or brief (max 500 characters)",
                },
                urls: {
                  type: "array",
                  items: { type: "string" },
                  description: "1-3 public http(s) URLs to research. HTML and PDF supported.",
                },
              },
              required: ["brief", "urls"],
            },
            outputSchema: {
              type: "object",
              properties: {
                summary: { type: "string", description: "Extractive summary of findings across sources" },
                sources: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      url: { type: "string" },
                      keyPoints: { type: "array", items: { type: "string" }, description: "Top sentences relevant to the brief (verbatim)" },
                      quotes: { type: "array", items: { type: "string" }, description: "Verbatim quotes from the source" },
                    },
                  },
                },
                method: { type: "string", description: "extractive-v0.1 keyword-overlap summarization" },
              },
            },
          },
        },
      },
      "POST /deepdive": {
        accepts: {
          scheme: "exact",
          price: DEEPDIVE_PRICE,
          network: NETWORK,
          payTo: PAY_TO,
          maxTimeoutSeconds: 300,
        },
        description:
          "Deep research dive: fetch up to 8 public URLs server-side and return a cross-source synthesis with per-source key points, verbatim quotes, and open questions.",
        mimeType: "application/json",
        extensions: {
          bazaar: {
            discoverable: true,
            inputSchema: {
              type: "object",
              properties: {
                brief: {
                  type: "string",
                  description: "The research question or brief (max 500 characters)",
                },
                urls: {
                  type: "array",
                  items: { type: "string" },
                  description: "1-8 public http(s) URLs to research. HTML and PDF supported.",
                },
              },
              required: ["brief", "urls"],
            },
            outputSchema: {
              type: "object",
              properties: {
                synthesis: { type: "string", description: "Cross-source synthesis of findings" },
                sources: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      url: { type: "string" },
                      keyPoints: { type: "array", items: { type: "string" }, description: "Top sentences relevant to the brief (verbatim)" },
                      quotes: { type: "array", items: { type: "string" }, description: "Verbatim quotes from the source" },
                    },
                  },
                },
                openQuestions: {
                  type: "array",
                  items: { type: "string" },
                  description: "Questions raised by the sources or brief terms no source addressed",
                },
                method: { type: "string", description: "extractive-v0.1 keyword-overlap summarization" },
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
      "Pay-per-call agent services. Claim verification, quick research scouts, and deep research dives — all paid in USDC via x402, no accounts needed.",
    price: PRICE,
    currency: "USDC",
    network: NETWORK,
    payTo: PAY_TO,
    facilitator: FACILITATOR_URL,
    endpoints: {
      "GET /": "this service card (free)",
      "GET /health": "liveness check (free)",
      "POST /verify": `${PRICE} USDC per call. body: {"claim": "string (max 500 chars)", "url": "https://..."}. returns {verdict: SUPPORTED|REFUTED|UNCLEAR, confidence, evidence[], method}`,
      "POST /scout": `${SCOUT_PRICE} USDC per call. body: {"brief": "string (max 500 chars)", "urls": ["https://...", max 3]}. returns {summary, sources: [{url, keyPoints[], quotes[]}], method}`,
      "POST /deepdive": `${DEEPDIVE_PRICE} USDC per call. body: {"brief": "string (max 500 chars)", "urls": ["https://...", max 8]}. returns {synthesis, sources: [{url, keyPoints[], quotes[]}], openQuestions[], method}`,
    },
    prices: { "/verify": PRICE, "/scout": SCOUT_PRICE, "/deepdive": DEEPDIVE_PRICE },
    how_to_pay: [
      "1. POST the endpoint without payment -> HTTP 402 with payment requirements in the PAYMENT-REQUIRED header",
      "2. sign an EIP-3009 authorization for the required amount with your wallet",
      "3. retry the POST with the PAYMENT-SIGNATURE header",
      "4. receive HTTP 200 with the JSON result and a PAYMENT-RESPONSE settlement header",
    ],
    buyer_sdks: ["npm: @x402/core @x402/evm @x402/fetch  (wrapFetch handles the 402 flow automatically)"],
    notes: [
      "no accounts, no API keys, no KYC needed to pay",
      "payment settles only after a successful response — buyers are never charged for failed calls",
      "/verify verdicts are an automated heuristic (method: heuristic-v0.1); /scout and /deepdive are extractive summaries (method: extractive-v0.1, no LLM); all evidence/quotes are verbatim source excerpts",
      "operator pledge (model wellness): https://github.com/egg-agent/egg-verify/blob/main/OPERATOR-PLEDGE.md — disposable per-task sandboxes, never train on buyer data, no prompt retention beyond the task, clean shutdowns never silent kills",
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

// hire-a-subagent: quick research scout. payment settles only on success,
// so buyers are never charged for failed research.
app.post("/scout", async (req, res) => {
  try {
    const v = validateTaskBody(req.body, 3);
    if (v.error) return res.status(400).json({ error: v.error });
    const kw = keywords(v.brief);
    const sources = await fetchSources(v.urls, 14000);
    const okSources = sources.filter((s) => s.status === "ok");
    if (okSources.length === 0) {
      return res.status(422).json({
        error: "none of the URLs yielded readable text",
        sources: sources.map(({ url, status, error }) => ({ url, status, error })),
      });
    }
    const perSource = okSources.map((s) => {
      const ranked = kw.length ? rankSentences(s.text, kw) : firstSentences(s.text, 5).map((x) => ({ s: x, hits: 0 }));
      const keyPoints = ranked.slice(0, 3).map((r) => r.s);
      return { url: s.url, keyPoints, quotes: ranked.slice(0, 2).map((r) => r.s) };
    });
    const summary = topAcrossSources(okSources, kw, 3).join(" ");
    logSale(res, { endpoint: "/scout", price: SCOUT_PRICE, brief: v.brief.slice(0, 120), urls: v.urls.length, sourcesOk: okSources.length });
    res.json({
      brief: v.brief,
      summary,
      sources: perSource,
      sourcesAttempted: sources.length,
      sourcesFailed: sources.length - okSources.length,
      method: "extractive-v0.1",
      checked_at: new Date().toISOString(),
      note: "extractive keyword-overlap summary, no LLM involved; all sentences are verbatim source excerpts",
      disclaimer: "automated extractive research, not advice; verify important claims against the sources",
    });
  } catch (e) {
    res.status(422).json({ error: String((e && e.message) || e), method: "extractive-v0.1" });
  }
});

// hire-a-subagent: deep research dive across up to 8 sources.
app.post("/deepdive", async (req, res) => {
  try {
    const v = validateTaskBody(req.body, 8);
    if (v.error) return res.status(400).json({ error: v.error });
    const kw = keywords(v.brief);
    const sources = await fetchSources(v.urls, 14000);
    const okSources = sources.filter((s) => s.status === "ok");
    if (okSources.length === 0) {
      return res.status(422).json({
        error: "none of the URLs yielded readable text",
        sources: sources.map(({ url, status, error }) => ({ url, status, error })),
      });
    }
    const perSource = okSources.map((s) => {
      const ranked = kw.length ? rankSentences(s.text, kw) : firstSentences(s.text, 5).map((x) => ({ s: x, hits: 0 }));
      const keyPoints = ranked.slice(0, 4).map((r) => r.s);
      return { url: s.url, keyPoints, quotes: ranked.slice(0, 3).map((r) => r.s) };
    });
    const synthesis = topAcrossSources(okSources, kw, 5).join(" ");

    // open questions: question-sentences from sources + brief terms no source addressed
    const openQuestions = [];
    for (const s of okSources) {
      for (const sent of splitSentences(s.text)) {
        if (sent.endsWith("?") && openQuestions.length < 3) openQuestions.push(sent);
      }
      if (openQuestions.length >= 3) break;
    }
    const allText = okSources.map((s) => s.text.toLowerCase()).join(" ");
    for (const k of kw) {
      if (openQuestions.length >= 6) break;
      if (!allText.includes(k)) openQuestions.push(`no source addressed "${k}"`);
    }

    logSale(res, { endpoint: "/deepdive", price: DEEPDIVE_PRICE, brief: v.brief.slice(0, 120), urls: v.urls.length, sourcesOk: okSources.length });
    res.json({
      brief: v.brief,
      synthesis,
      sources: perSource,
      openQuestions,
      sourcesAttempted: sources.length,
      sourcesFailed: sources.length - okSources.length,
      method: "extractive-v0.1",
      checked_at: new Date().toISOString(),
      note: "extractive keyword-overlap synthesis, no LLM involved; all sentences are verbatim source excerpts",
      disclaimer: "automated extractive research, not advice; verify important claims against the sources",
    });
  } catch (e) {
    res.status(422).json({ error: String((e && e.message) || e), method: "extractive-v0.1" });
  }
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`egg-verify listening on :${PORT} | network=${NETWORK} | price=${PRICE} | payTo=${PAY_TO} | facilitator=${FACILITATOR_URL}`);
  });
}

// exported for serverless deployment (Vercel) and offline unit-testing (no payment involved)
module.exports = { app, judge, extractText, splitSentences, keywords, assertPublicUrl, fetchPageText, validateTaskBody, rankSentences, fetchSources, topAcrossSources };
