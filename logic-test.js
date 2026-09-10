// logic-test.js — unit-test the REAL judge() from server.js against live pages.
// No payment involved; exercises fetch + extract + judge only.
const { judge, extractText, assertPublicUrl, fetchPageText } = require("./server.js");

async function check(claim, url) {
  const u = await assertPublicUrl(url);
  const text = extractText(await fetchPageText(u));
  const r = judge(claim, text);
  console.log("CLAIM:", claim);
  console.log("URL:", u.toString());
  console.log("VERDICT:", r.verdict, "| confidence:", r.confidence, "| note:", r.note);
  console.log("EVIDENCE:");
  r.evidence.forEach((e, i) => console.log(`  [${i + 1}] ${e.slice(0, 220)}`));
  console.log("---");
}

async function main() {
  // true claim (verified in the earlier opportunity-monitor research)
  await check(
    "Denver Urban Market charges vendors $130 per day",
    "https://www.coloradoevents.org/_files/ugd/d38fcb_7b91929697a64d0885eada1afc149fc6.pdf"
  );
  // false claim about the same source
  await check(
    "Denver Urban Market is free for all vendors with no booth fee",
    "https://www.coloradoevents.org/_files/ugd/d38fcb_7b91929697a64d0885eada1afc149fc6.pdf"
  );
  // unrelated claim -> should be UNCLEAR
  await check(
    "The Eiffel Tower was completed in 1889",
    "https://www.fireflyhandmade.com/for-artisans"
  );
}

main().catch((e) => { console.error("ERR:", e.message); process.exit(1); });
