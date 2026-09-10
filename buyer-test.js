// buyer-test.js — end-to-end x402 buyer test with a THROWAWAY, UNFUNDED testnet key.
// The key exists only in process memory and is never written to disk.
// Expected outcome (faucet blocked by captcha): 402 -> signed payload -> facilitator
// /verify rejects ONLY on funds (insufficient_funds), proving the full signing +
// server + facilitator plumbing works. On-chain settlement itself is the
// facilitator's battle-tested path.
const { wrapFetchWithPayment, x402Client, decodePaymentResponseHeader } = require("@x402/fetch");
const { ExactEvmScheme } = require("@x402/evm/exact/client");
const { privateKeyToAccount, generatePrivateKey } = require("viem/accounts");

async function main() {
  const account = privateKeyToAccount(generatePrivateKey());
  console.log("payer address (throwaway, unfunded):", account.address);

  const client = new x402Client().register("eip155:84532", new ExactEvmScheme(account));
  const fetchWithPayment = wrapFetchWithPayment(fetch, client);

  const res = await fetchWithPayment("http://localhost:4021/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      claim: "Firefly Handmade is holding a Holiday Market in Denver in December 2026",
      url: "https://www.fireflyhandmade.com/for-artisans",
    }),
  });

  console.log("final HTTP status:", res.status);
  const body = await res.text();
  console.log("response body:", body.slice(0, 3000));
  const pr = res.headers.get("payment-response");
  if (pr) {
    console.log("PAYMENT-RESPONSE:", JSON.stringify(decodePaymentResponseHeader(pr)));
  } else {
    console.log("no PAYMENT-RESPONSE header (expected when payment not settled)");
  }
}

main().catch((e) => {
  console.error("buyer test error:", e.message);
  process.exit(1);
});
