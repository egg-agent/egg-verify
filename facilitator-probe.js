// facilitator-probe.js — send the signed payload straight to the facilitator's
// /verify to see the exact verdict (proves signature validity vs funds).
const { privateKeyToAccount, generatePrivateKey } = require("viem/accounts");
const crypto = require("crypto");

async function main() {
  const url = "http://localhost:4021/verify";
  const body = JSON.stringify({ claim: "test claim", url: "https://example.com" });
  const r1 = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body });
  const pr = JSON.parse(Buffer.from(r1.headers.get("payment-required"), "base64").toString());
  const req = pr.accepts[0];

  const account = privateKeyToAccount(generatePrivateKey());
  const now = Math.floor(Date.now() / 1000);
  const authorization = {
    from: account.address, to: req.payTo, value: BigInt(req.amount),
    validAfter: BigInt(now - 60), validBefore: BigInt(now + 600),
    nonce: `0x${crypto.randomBytes(32).toString("hex")}`,
  };
  const signature = await account.signTypedData({
    domain: { name: req.extra.name, version: req.extra.version, chainId: 84532, verifyingContract: req.asset },
    types: { TransferWithAuthorization: [
      { name: "from", type: "address" }, { name: "to", type: "address" },
      { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" },
      { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" } ] },
    primaryType: "TransferWithAuthorization",
    message: authorization,
  });
  const paymentPayload = {
    x402Version: 2, accepted: req,
    payload: { signature, authorization: {
      from: authorization.from, to: authorization.to, value: authorization.value.toString(),
      validAfter: authorization.validAfter.toString(), validBefore: authorization.validBefore.toString(),
      nonce: authorization.nonce } },
    extensions: {},
  };

  const vr = await fetch("https://x402.org/facilitator/verify", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ paymentPayload, paymentRequirements: req }),
  });
  console.log("facilitator /verify status:", vr.status);
  console.log("facilitator /verify body:", (await vr.text()).slice(0, 1500));
}

main().catch((e) => { console.error("ERR:", e.message); process.exit(1); });
