// TrustPass: verifiable CV credentials on Hedera testnet.
// Usage: node trustpass.js setup | issue | verify <file> | revoke <file> | agent [cv.txt] | pay
import "dotenv/config";
import fs from "node:fs";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  Client, AccountId, PrivateKey, Hbar,
  TopicCreateTransaction, TopicMessageSubmitTransaction, TransferTransaction,
} from "@hashgraph/sdk";

const MIRROR = "https://testnet.mirrornode.hedera.com";
const scan = (p) => `https://hashscan.io/testnet/${p}`;
const txLink = (id) => scan("transaction/" + id.toString().replace(/@(\d+)\.(\d+)$/, "-$1-$2"));
const readJson = (f, d) => { try { return JSON.parse(fs.readFileSync(f, "utf8")); } catch { return d; } };
const [cmd, ...args] = process.argv.slice(2);

const SAMPLE_CV = `Sarra Ben Ali, finance graduate
DEGREE | Master in Finance | IHEC Sousse | 2025
DEGREE | MBA | HEC Paris | 2024
DEGREE | PhD in Finance | IHEC Sousse | 2025`;

function getClient() {
  const k = (process.env.OPERATOR_KEY || "").trim().replace(/^0x/, "");
  if (!process.env.OPERATOR_ID || !k) throw new Error("Create a .env file with OPERATOR_ID and OPERATOR_KEY (see README).");
  const key = k.startsWith("302") ? PrivateKey.fromStringDer(k) : PrivateKey.fromStringECDSA(k);
  return Client.forTestnet().setOperator(AccountId.fromString(process.env.OPERATOR_ID), key);
}

// Same credential -> same text -> same fingerprint, whatever the key order.
const canon = (o) =>
  Array.isArray(o) ? `[${o.map(canon)}]`
  : o && typeof o === "object" ? `{${Object.keys(o).sort().map((k) => JSON.stringify(k) + ":" + canon(o[k]))}}`
  : JSON.stringify(o);
const hashOf = (c) => createHash("sha256").update(canon(c)).digest("hex");

// Reads all messages of an issuer's HCS topic through the Mirror Node.
async function readRegistry(topic) {
  let url = `${MIRROR}/api/v1/topics/${topic}/messages?limit=100&order=asc`;
  const events = [];
  while (url) {
    const r = await fetch(url);
    if (!r.ok) throw new Error(`Mirror Node error ${r.status} for topic ${topic}`);
    const j = await r.json();
    for (const m of j.messages ?? []) {
      try { events.push({ ...JSON.parse(Buffer.from(m.message, "base64").toString()), seq: m.sequence_number }); } catch {}
    }
    url = j.links?.next ? MIRROR + j.links.next : null;
  }
  return events;
}

// The cryptographic check: trusted issuer + fingerprint on Hedera + not revoked.
async function check(cred, cache = {}) {
  const topic = cred.issuer?.topic;
  if (!readJson("trusted-issuers.json", {})[topic]) return { status: "UNTRUSTED ISSUER" };
  cache[topic] ??= await readRegistry(topic);
  const h = hashOf(cred);
  const ev = cache[topic].filter((e) => e.h === h);
  const issued = ev.find((e) => e.t === "issue");
  if (!issued) return { status: "NOT FOUND ON HEDERA" };
  if (ev.some((e) => e.t === "revoke")) return { status: "REVOKED" };
  return { status: "VERIFIED", seq: issued.seq, link: scan("topic/" + topic) };
}

// The AI proposes: it reads the CV and lists the claims.
async function extractClaims(text) {
  if (!process.env.ANTHROPIC_API_KEY) {
    console.log("(No ANTHROPIC_API_KEY: using the simple built-in parser)\n");
    return text.split("\n").filter((l) => l.startsWith("DEGREE |")).map((l) => {
      const [, degree, institution, year] = l.split("|").map((s) => s.trim());
      return { degree, institution, year: Number(year) };
    });
  }
  const r = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "x-api-key": process.env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json" },
    body: JSON.stringify({
      model: process.env.LLM_MODEL || "claude-sonnet-5-5", max_tokens: 1000,
      messages: [{ role: "user", content: `Extract every degree claim from this CV (any language). Reply with ONLY a JSON array of {"degree":"","institution":"","year":0}.\n\n${text}` }],
    }),
  });
  if (!r.ok) throw new Error(`LLM API error ${r.status}: ${await r.text()}`);
  const out = (await r.json()).content.map((b) => b.text ?? "").join("");
  return JSON.parse(out.replace(/```json|```/g, "").trim());
}

const commands = {
  // Creates the issuer registry (an HCS topic only the issuer can write to).
  async setup() {
    const name = args[0] || "IHEC Sousse";
    const c = getClient();
    const tx = await new TopicCreateTransaction()
      .setTopicMemo("TrustPass issuer registry: " + name)
      .setSubmitKey(c.operatorPublicKey)
      .execute(c);
    const topic = (await tx.getReceipt(c)).topicId.toString();
    const trusted = readJson("trusted-issuers.json", {});
    trusted[topic] = name;
    fs.writeFileSync("trusted-issuers.json", JSON.stringify(trusted, null, 2));
    console.log(`Issuer registry created for ${name}\nTopic: ${topic}\n${scan("topic/" + topic)}`);
  },

  // Issues a credential: only its fingerprint goes on Hedera.
  async issue() {
    const [holder = "Sarra Ben Ali", degree = "Master in Finance", year = "2025"] = args;
    const trusted = readJson("trusted-issuers.json", {});
    const topic = Object.keys(trusted)[0];
    if (!topic) throw new Error("Run `npm run setup` first.");
    const cred = {
      id: randomUUID(), type: "UniversityDegree",
      issuer: { name: trusted[topic], topic },
      holder, claims: { degree, year: Number(year) },
      salt: randomBytes(16).toString("hex"), // makes the fingerprint impossible to guess
      issuedAt: new Date().toISOString(),
    };
    const c = getClient();
    const tx = await new TopicMessageSubmitTransaction()
      .setTopicId(topic).setMessage(JSON.stringify({ t: "issue", h: hashOf(cred) })).execute(c);
    await tx.getReceipt(c);
    fs.mkdirSync("credentials", { recursive: true });
    const file = `credentials/${cred.id}.json`;
    fs.writeFileSync(file, JSON.stringify(cred, null, 2));
    console.log(`Credential issued to ${holder}\nStudent wallet file: ${file}\nOnly its fingerprint is on Hedera: ${txLink(tx.transactionId)}\nWait ~5 seconds, then: npm run verify -- ${file}`);
  },

  async verify() {
    if (!args[0]) throw new Error("Usage: npm run verify -- credentials/<file>.json");
    const cred = JSON.parse(fs.readFileSync(args[0], "utf8"));
    const r = await check(cred);
    console.log(`${r.status}: ${cred.claims.degree} (${cred.claims.year}), ${cred.issuer.name}`);
    if (r.link) console.log(`Proof: ${r.link} (message #${r.seq})`);
  },

  async revoke() {
    if (!args[0]) throw new Error("Usage: npm run revoke -- credentials/<file>.json");
    const cred = JSON.parse(fs.readFileSync(args[0], "utf8"));
    const c = getClient();
    const tx = await new TopicMessageSubmitTransaction()
      .setTopicId(cred.issuer.topic).setMessage(JSON.stringify({ t: "revoke", h: hashOf(cred) })).execute(c);
    await tx.getReceipt(c);
    console.log("Credential revoked on Hedera. Verify it again in ~5 seconds.");
  },

  // The AI proposes, the cryptography decides.
  async agent() {
    const text = args[0] ? fs.readFileSync(args[0], "utf8") : SAMPLE_CV;
    const claims = await extractClaims(text);
    const trusted = Object.values(readJson("trusted-issuers.json", {}));
    const wallet = fs.existsSync("credentials")
      ? fs.readdirSync("credentials").map((f) => JSON.parse(fs.readFileSync(`credentials/${f}`, "utf8")))
      : [];
    const same = (a, b) => String(a).toLowerCase().trim() === String(b).toLowerCase().trim();
    const cache = {};
    let proven = 0;
    for (const c of claims) {
      const match = wallet.find((w) => same(w.claims.degree, c.degree) && same(w.issuer.name, c.institution) && w.claims.year === c.year);
      let verdict;
      if (match) {
        const r = await check(match, cache);
        verdict = r.status === "VERIFIED" ? (proven++, `✅ VERIFIED on Hedera ${r.link}`) : `❌ ${r.status}`;
      } else if (trusted.some((n) => same(n, c.institution))) {
        verdict = "❌ RED FLAG: this issuer is on TrustPass but never issued this credential";
      } else {
        verdict = "⚠️ UNVERIFIED: this issuer is not on TrustPass yet";
      }
      console.log(`${verdict}\n   ${c.degree}, ${c.institution}, ${c.year}\n`);
    }
    console.log(`Trust score: ${proven}/${claims.length} claims proven on Hedera`);
  },

  // One verification fee, split between student, issuer and platform in ONE transaction.
  async pay() {
    const { OPERATOR_ID, STUDENT_ACCOUNT, ISSUER_ACCOUNT, PLATFORM_ACCOUNT } = process.env;
    if (!STUDENT_ACCOUNT || !ISSUER_ACCOUNT || !PLATFORM_ACCOUNT) throw new Error("Add STUDENT_ACCOUNT, ISSUER_ACCOUNT and PLATFORM_ACCOUNT to your .env file.");
    const fee = 10_000_000; // 0.1 HBAR in tinybars, paid by the recruiter
    const c = getClient();
    const tx = new TransferTransaction().addHbarTransfer(OPERATOR_ID, Hbar.fromTinybars(-fee));
    for (const [account, share] of [[STUDENT_ACCOUNT, 0.5], [ISSUER_ACCOUNT, 0.3], [PLATFORM_ACCOUNT, 0.2]]) {
      tx.addHbarTransfer(account, Hbar.fromTinybars(Math.round(fee * share)));
    }
    const res = await tx.execute(c);
    await res.getReceipt(c);
    console.log(`One transaction, three payees: student 50%, issuer 30%, platform 20%\n${txLink(res.transactionId)}`);
  },
};

if (!Object.hasOwn(commands, cmd)) {
  console.log("Usage: node trustpass.js setup | issue | verify <file> | revoke <file> | agent [cv.txt] | pay");
  process.exit(1);
}
await commands[cmd]();
process.exit(0);
