# TrustPass
# TrustPass

**Proof Over Promises** Built by Veritas Labs for the IHEC Sousse hackathon, on Hedera.

A university anchors the fingerprint (SHA-256 hash) of each credential on the Hedera Consensus Service. The student keeps the credential. An AI agent reads a CV and checks every claim against the proof on Hedera. No personal data goes on-chain. The AI proposes, the cryptography decides.

## What it does (all in `trustpass.js`, on Hedera testnet)

- Issuer registry and credential anchoring (Hedera Consensus Service)
- Verification and revocation (Mirror Node)
- CV-checking agent (LLM API, or a simple parser without a key)
- Pay-per-verification: one fee split between student, issuer and platform in a single transaction

Roadmap: did:hedera identities, HTS badges, selective disclosure, x402 payments.

## Run it
Live demo: https://salmaaa2008.github.io/TrustPass/

1. Install Node.js 20+ and create a free testnet account at portal.hedera.com.
2. Create a file named `.env` containing:
   ```
   OPERATOR_ID=0.0.your-account-id
   OPERATOR_KEY=your-private-key
   ```
3. `npm install`
4. `npm run setup`, then `npm run issue`, wait 5 seconds, then `npm run verify -- credentials/<file>.json`
5. `npm run agent`: one claim verified, one unverified, one red flag.
