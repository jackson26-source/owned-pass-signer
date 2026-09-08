// Minimal CMS (PKCS#7) SignedData builder using only WebCrypto + hand-rolled
// DER encoding — no Node-specific crypto APIs, so this exact code can run
// unchanged in a Cloudflare Worker.
//
// Builds a detached SHA-1/RSA CMS signature over an arbitrary buffer,
// matching what Apple's `signpass`/`openssl smime -sign` produce for a
// PassKit manifest.json — the format PassKit itself expects.

const OID = {
  data: [1, 2, 840, 113549, 1, 7, 1],
  signedData: [1, 2, 840, 113549, 1, 7, 2],
  sha1: [1, 3, 14, 3, 2, 26],
  rsaEncryption: [1, 2, 840, 113549, 1, 1, 1],
  sha1WithRSAEncryption: [1, 2, 840, 113549, 1, 1, 5],
  contentType: [1, 2, 840, 113549, 1, 9, 3],
  messageDigest: [1, 2, 840, 113549, 1, 9, 4],
  signingTime: [1, 2, 840, 113549, 1, 9, 5],
};

function encLen(len) {
  if (len < 128) return new Uint8Array([len]);
  const bytes = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function tlv(tag, contentParts) {
  const content = concat(contentParts);
  return concat([new Uint8Array([tag]), encLen(content.length), content]);
}

function concat(parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function encodeOID(oid) {
  const bytes = [oid[0] * 40 + oid[1]];
  for (let i = 2; i < oid.length; i++) {
    let v = oid[i];
    const chunk = [v & 0x7f];
    v >>= 7;
    while (v > 0) {
      chunk.unshift((v & 0x7f) | 0x80);
      v >>= 7;
    }
    bytes.push(...chunk);
  }
  return tlv(0x06, [new Uint8Array(bytes)]);
}

function encodeInteger(bytesOrNum) {
  let bytes;
  if (typeof bytesOrNum === "number") {
    bytes = [];
    let n = bytesOrNum;
    do {
      bytes.unshift(n & 0xff);
      n >>= 8;
    } while (n > 0);
  } else {
    bytes = Array.from(bytesOrNum);
  }
  // Ensure positive (prepend 0x00 if high bit set)
  if (bytes[0] & 0x80) bytes.unshift(0x00);
  return tlv(0x02, [new Uint8Array(bytes)]);
}

function encodeNull() {
  return new Uint8Array([0x05, 0x00]);
}

function encodeOctetString(bytes) {
  return tlv(0x04, [bytes]);
}

function encodeUTCTime(date) {
  const pad = (n) => String(n).padStart(2, "0");
  const s =
    pad(date.getUTCFullYear() % 100) +
    pad(date.getUTCMonth() + 1) +
    pad(date.getUTCDate()) +
    pad(date.getUTCHours()) +
    pad(date.getUTCMinutes()) +
    pad(date.getUTCSeconds()) +
    "Z";
  return tlv(0x17, [new TextEncoder().encode(s)]);
}

function algId(oidArr, withNull = true) {
  return tlv(0x30, [encodeOID(oidArr), ...(withNull ? [encodeNull()] : [])]);
}

// --- minimal DER walker, just enough to pull issuer+serialNumber out of a real cert ---
function readTLV(buf, offset) {
  const tag = buf[offset];
  let lenByte = buf[offset + 1];
  let headerLen = 2;
  let length;
  if (lenByte & 0x80) {
    const numBytes = lenByte & 0x7f;
    length = 0;
    for (let i = 0; i < numBytes; i++) length = (length << 8) | buf[offset + 2 + i];
    headerLen = 2 + numBytes;
  } else {
    length = lenByte;
  }
  const contentStart = offset + headerLen;
  const contentEnd = contentStart + length;
  return { tag, length, headerLen, contentStart, contentEnd, raw: buf.slice(offset, contentEnd) };
}

/** Extracts { issuerRawDER, serialRawDER } straight out of a DER-encoded X.509 certificate. */
function extractIssuerAndSerial(certDER) {
  const outer = readTLV(certDER, 0); // Certificate SEQUENCE
  const tbs = readTLV(certDER, outer.contentStart); // TBSCertificate SEQUENCE
  let p = tbs.contentStart;
  let node = readTLV(certDER, p);
  if (node.tag === 0xa0) {
    // explicit [0] version — skip
    p = node.contentEnd;
    node = readTLV(certDER, p);
  }
  // node is now serialNumber INTEGER
  const serialRawDER = node.raw;
  p = node.contentEnd;
  node = readTLV(certDER, p); // signature AlgorithmIdentifier — skip
  p = node.contentEnd;
  node = readTLV(certDER, p); // issuer Name
  const issuerRawDER = node.raw;
  return { issuerRawDER, serialRawDER };
}

function sortSetOfDER(items) {
  // DER canonical SET OF ordering: ascending by encoded octets.
  return items.slice().sort((a, b) => {
    const len = Math.min(a.length, b.length);
    for (let i = 0; i < len; i++) {
      if (a[i] !== b[i]) return a[i] - b[i];
    }
    return a.length - b.length;
  });
}

/**
 * Builds a detached CMS SignedData (PKCS#7) signature, DER-encoded,
 * matching `openssl smime -sign -binary -in <content> -out <sig> -outform DER
 * -signer signerCert -inkey signerKey -certfile wwdrCert`.
 *
 * @param {Uint8Array} content - the raw bytes being signed (e.g. manifest.json)
 * @param {Uint8Array} signerCertDER
 * @param {Uint8Array} wwdrCertDER
 * @param {CryptoKey} privateKey - imported via crypto.subtle.importKey('pkcs8', ..., {name:'RSASSA-PKCS1-v1_5', hash:'SHA-1'}, false, ['sign'])
 * @param {Date} signingTime
 */
async function signManifestCMS(content, signerCertDER, wwdrCertDER, privateKey, signingTime = new Date()) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-1", content));

  const contentTypeAttr = tlv(0x30, [encodeOID(OID.contentType), tlv(0x31, [encodeOID(OID.data)])]);
  const signingTimeAttr = tlv(0x30, [encodeOID(OID.signingTime), tlv(0x31, [encodeUTCTime(signingTime)])]);
  const messageDigestAttr = tlv(0x30, [encodeOID(OID.messageDigest), tlv(0x31, [encodeOctetString(digest)])]);

  const sortedAttrs = sortSetOfDER([contentTypeAttr, signingTimeAttr, messageDigestAttr]);
  // The bytes that actually get signed use the UNIVERSAL SET tag (0x31) —
  // even though the SignerInfo structure stores this same value under an
  // IMPLICIT [0] context tag (0xA0). Classic CMS gotcha.
  const signedAttrsForSigning = tlv(0x31, sortedAttrs);
  const signedAttrsImplicit = tlv(0xa0, sortedAttrs); // same content, different outer tag

  const signature = new Uint8Array(await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, privateKey, signedAttrsForSigning));

  const { issuerRawDER, serialRawDER } = extractIssuerAndSerial(signerCertDER);
  const issuerAndSerialNumber = tlv(0x30, [issuerRawDER, serialRawDER]);

  const signerInfo = tlv(0x30, [
    encodeInteger(1),
    issuerAndSerialNumber,
    algId(OID.sha1),
    signedAttrsImplicit,
    algId(OID.sha1WithRSAEncryption),
    encodeOctetString(signature),
  ]);

  const digestAlgorithms = tlv(0x31, [algId(OID.sha1)]);
  const encapContentInfo = tlv(0x30, [encodeOID(OID.data)]); // detached: no [0] eContent
  const certificates = tlv(0xa0, [signerCertDER, wwdrCertDER]);
  const signerInfos = tlv(0x31, [signerInfo]);

  const signedData = tlv(0x30, [encodeInteger(1), digestAlgorithms, encapContentInfo, certificates, signerInfos]);

  const contentInfo = tlv(0x30, [encodeOID(OID.signedData), tlv(0xa0, [signedData])]);

  return contentInfo;
}

export { signManifestCMS };
