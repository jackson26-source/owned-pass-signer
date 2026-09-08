# Deploying owned-pass-signer

This is a small, standalone Cloudflare Worker with one job: build and sign
a real `.pkpass` file for the Owned app's "Add to Wallet" feature. It's
intentionally separate from `macless-backend` — different product, no
buyer login, no billing, nothing to break in either direction.

## What's already done (2026-09-08)

- A Pass Type ID (`pass.dev.macless.owned`) is registered in your Apple
  Developer account.
- Its certificate has been issued (expires 2027-10-07) and is bundled
  in this repo as `src/lib/certs.generated.js`, alongside Apple's public
  WWDR G4 intermediate certificate. Both are public — safe to commit.
- The matching **private key** is the one secret this Worker needs, and
  it's deliberately not in this repo. It's in the file delivered to you
  alongside this one, `owned-pass-signer-private-key.pem` — keep that
  file somewhere safe and don't commit it anywhere.
- Everything else (pass building, ZIP assembly, the CMS/PKCS#7 signature)
  is implemented from scratch in `src/lib/` using only Web Crypto — no
  external dependencies, no native modules, tested end-to-end against a
  real signature verification (`openssl smime -verify` and
  `openssl cms -verify` both pass) before this was ever written here.

## Steps for you

1. **Create the Worker.** In the Cloudflare dashboard (same account as
   `macless.dev`'s other Workers): Workers & Pages → Create → import this
   GitHub repo (`jackson26-source/owned-pass-signer`), or use
   `npx wrangler deploy` from a clone of it if you'd rather do it from a
   terminal.
2. **Paste in the private key as a secret** — this is the one manual step
   that has to be you, not a Claude session:
   - Dashboard: the Worker's Settings → Variables and Secrets → Add →
     name it `PASS_PRIVATE_KEY_PEM`, type **Secret**, paste in the full
     contents of `owned-pass-signer-private-key.pem` (the whole
     `-----BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY-----` block).
   - Or from a terminal: `npx wrangler secret put PASS_PRIVATE_KEY_PEM`,
     then paste the same file's contents when prompted.
3. **Point it at a real URL.** A Worker route like
   `pass-signer.macless.dev/*` (or just use its default
   `owned-pass-signer.<your-subdomain>.workers.dev` URL) — whichever you
   add, that's the `PASS_SIGNING_ENDPOINT` value the Owned app needs (see
   the app-side PR).
4. **Sanity check:** `curl https://<your-worker-url>/health` should return
   `{"ok":true,"configured":true}` once the secret is set. Before the
   secret is set it correctly returns `{"ok":true,"configured":false}`
   instead of erroring.
5. **Real test:**
   ```
   curl -X POST https://<your-worker-url>/api/sign-pass \
     -H "Content-Type: application/json" \
     -d '{"itemName":"Test Item","retailer":"Test Store","deadlineKind":"return","dueDateISO":"2026-12-01T00:00:00Z","serialNumber":"smoke-test-1"}' \
     -o test.pkpass
   ```
   Double-click the resulting `test.pkpass` on a Mac, or AirDrop it to an
   iPhone — it should open straight into Wallet's "Add" screen. That's
   the actual end-to-end proof, not just a 200 status code.

## What this Worker deliberately does NOT do

- Doesn't store anything. No KV, no D1, no logs of pass contents. Every
  request is signed and forgotten.
- Doesn't authenticate callers. It's a stateless signing utility, not a
  gated feature — same posture as `/api/diagnose-rejection` in
  macless-backend. If abuse ever becomes a real problem, the fix is a
  Cloudflare rate limit rule on the route, not app-level auth.
- Doesn't touch macless-backend's database, buyers, or billing in any way.

## If the Pass Type ID certificate ever expires (2027-10-07)

Same process as this session did it: Apple Developer Portal → Certificates
→ create a new Pass Type ID Certificate against the same `pass.dev.macless.owned`
identifier → generate a new CSR/key pair → download the new cert → update
`src/lib/certs.generated.js`'s `SIGNER_CERT_B64` → generate a fresh
`PASS_PRIVATE_KEY_PEM` and paste it in as the new secret, same as step 2.
