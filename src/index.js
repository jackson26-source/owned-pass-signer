// Owned — Wallet pass signer.
//
// A tiny, standalone Worker with exactly one job: build and cryptographically
// sign a .pkpass file on request, so the Owned app can offer a real "Add to
// Wallet" button. Deliberately separate from macless-backend (the Macless
// SaaS wizard) — different product, no buyer auth or billing involved, and
// keeping it standalone means this Worker's only failure mode is "wallet
// passes don't sign," never "the Macless buyer wizard is down."
//
// Why this has to be server-side at all: a real .pkpass has to be signed
// with the Pass Type ID certificate's PRIVATE KEY. Bundling that key inside
// the Owned app binary (so signing could happen fully on-device, matching
// Owned's "no server" Phase 1 story) would mean anyone who extracts the IPA
// gets a key that can forge passes claiming to be from Owned — so the
// signing step, and only the signing step, happens here instead. Nothing
// about an item (name, dates, retailer) is stored anywhere in this Worker;
// every request is signed and immediately forgotten.
//
// The private key itself is a Worker secret (PASS_PRIVATE_KEY_PEM) that
// Jackson generates and pastes in himself — see DEPLOY.md. It is never
// typed in by a Claude session, matching every other credential in this
// project.

import { buildSignedPass } from "./lib/build-pass.js";
import { SIGNER_CERT_B64, WWDR_CERT_B64 } from "./lib/certs.generated.js";
import { PASS_ASSETS_B64 } from "./lib/pass-assets.generated.js";

const ALLOWED_DEADLINE_KINDS = new Set(["return", "warranty"]);
const MAX_STRING_LEN = 200;
const MAX_NOTES_LEN = 1000;

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json" } });
}

function b64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function pemToDER(pem) {
  const b64 = pem
    .replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "")
    .replace(/\s+/g, "");
  return b64ToBytes(b64);
}

function clampString(v, max) {
  return typeof v === "string" ? v.slice(0, max).trim() : "";
}

let cachedPrivateKey = null;
async function getPrivateKey(env) {
  if (cachedPrivateKey) return cachedPrivateKey;
  if (!env.PASS_PRIVATE_KEY_PEM) throw new Error("PASS_PRIVATE_KEY_PEM secret is not set");
  const pkcs8 = pemToDER(env.PASS_PRIVATE_KEY_PEM);
  cachedPrivateKey = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" },
    false,
    ["sign"]
  );
  return cachedPrivateKey;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/health" && request.method === "GET") {
      return json({ ok: true, configured: !!env.PASS_PRIVATE_KEY_PEM });
    }

    if (url.pathname !== "/api/sign-pass" || request.method !== "POST") {
      return json({ ok: false, detail: "no such endpoint" }, 404);
    }

    let body;
    try {
      body = await request.json();
    } catch (e) {
      return json({ ok: false, detail: "Malformed JSON body." }, 400);
    }

    const itemName = clampString(body.itemName, MAX_STRING_LEN);
    const retailer = clampString(body.retailer, MAX_STRING_LEN);
    const deadlineKind = clampString(body.deadlineKind, 20);
    const serialNumber = clampString(body.serialNumber, MAX_STRING_LEN);
    const notes = clampString(body.notes, MAX_NOTES_LEN);
    const dueDateISO = body.dueDateISO;

    if (!itemName) return json({ ok: false, detail: "itemName is required." }, 400);
    if (!serialNumber) return json({ ok: false, detail: "serialNumber is required." }, 400);
    if (!ALLOWED_DEADLINE_KINDS.has(deadlineKind)) {
      return json({ ok: false, detail: `deadlineKind must be one of: ${[...ALLOWED_DEADLINE_KINDS].join(", ")}` }, 400);
    }
    const parsedDate = typeof dueDateISO === "string" ? new Date(dueDateISO) : null;
    if (!parsedDate || Number.isNaN(parsedDate.getTime())) {
      return json({ ok: false, detail: "dueDateISO must be a valid ISO 8601 date string." }, 400);
    }

    let privateKey;
    try {
      privateKey = await getPrivateKey(env);
    } catch (e) {
      // Not configured yet — tell the caller plainly rather than a raw 500.
      return json({ ok: false, code: "not_configured", detail: "Wallet signing isn't set up on the server yet." }, 503);
    }

    try {
      const signerCertDER = b64ToBytes(SIGNER_CERT_B64);
      const wwdrCertDER = b64ToBytes(WWDR_CERT_B64);
      const assets = {};
      for (const [name, b64] of Object.entries(PASS_ASSETS_B64)) assets[name] = b64ToBytes(b64);

      const pkpass = await buildSignedPass(
        { itemName, retailer, deadlineKind, dueDateISO, serialNumber, notes },
        assets,
        signerCertDER,
        wwdrCertDER,
        privateKey
      );

      return new Response(pkpass, {
        status: 200,
        headers: {
          "Content-Type": "application/vnd.apple.pkpass",
          "Content-Disposition": `attachment; filename="${serialNumber}.pkpass"`,
        },
      });
    } catch (e) {
      return json({ ok: false, detail: `Couldn't build the pass: ${(e && e.message) || e}` }, 500);
    }
  },
};
