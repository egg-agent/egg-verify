// manual-buyer-test.js — transparent step-by-step x402 flow (no client black box).
// 1) unpaid POST -> 402, decode PAYMENT-REQUIRED
// 2) sign EIP-3009 authorization with throwaway unfunded key
// 3) retry with PAYMENT-SIGNATURE -> observe facilitator verdict
const { privateKeyToAccount, generatePrivateKey } = require("viem/accounts");
const crypto = require("crypto");

async function main() {
  const url = "http://localhost:4021/verify";
  const body = JSON.stringify({ claim: "test claim", url: "https://example.com" });

  const r1 = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body });
  console.log("step 1 status:", r1.status);
  const pr = JSON.parse(Buffer.from(r1.headers.get("payment-required"), "base64").toString());
  const req = pr.accepts[0];
  console.log("requirements:", JSON.stringify({ network: req.network, amount: req.amount, asset: req.asset, payTo: req.payTo, scheme: req.scheme }));

  const account = privateKeyToAccount(generatePrivateKey());
  console.log("payer (throwaway, unfunded):", account.address);
  const now = Math.floor(Date.now() / 1000);
  const authorization = {
    from: account.address,
    to: req.payTo,
    value: BigInt(req.amount),
    validAfter: BigInt(now - 60),
    validBefore: BigInt(now + 600),
    nonce: `0x${crypto.randomBytes(32).toString("hex")}`,
  };
  const signature = await account.signTypedData({
    domain: { name: req.extra.name, version: req.extra.version, chainId: 84532, verifyingContract: req.asset },
    types: {
      TransferWithAuthorization: [
        { name: "from", type: "address" },
        { name: "to", type: "address" },
        { name: "value", type: "uint256" },
        { name: "validAfter", type: "uint256" },
        { name: "validBefore", type: "uint256" },
        { name: "nonce", type: "bytes32" },
      ],
    },
    primaryType: "TransferWithAuthorization",
    message: authorization,
  });
  console.log("signed EIP-3009 authorization, sig:", signature.slice(0, 20) + "...");

  const payload = {
    x402Version: 2,
    accepted: req,
    payload: {
      signature,
      authorization: {
        from: authorization.from, to: authorization.to,
        value: authorization.value.toString(),
        validAfter: authorization.validAfter.toString(),
        validBefore: authorization.validBefore.toString(),
        nonce: authorization.nonce,
      },
    },
    extensions: {},
  };
  const sigHeader = Buffer.from(JSON.stringify(payload)).toString("base64");

  const r2 = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", "PAYMENT-SIGNATURE": sigHeader },
    body,
  });
  console.log("step 3 status:", r2.status);
  console.log("step 3 body:", (await r2.text()).slice(0, 2000));
  const prh = r2.headers.get("payment-response");
  console.log("PAYMENT-RESPONSE header:", prh ? prh.slice(0, 200) : "(absent)");
}

main().catch((e) => { console.error("ERR:", e.message); process.exit(1); });
