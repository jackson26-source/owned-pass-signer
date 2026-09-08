import { buildZip } from "./zip.js";
import { signManifestCMS } from "./cms.js";

const PASS_TYPE_IDENTIFIER = "pass.dev.macless.owned";
const TEAM_IDENTIFIER = "8N6W89UUA5";

function sha1Hex(buf) {
  // caller awaits — kept async via digest below
  return crypto.subtle.digest("SHA-1", buf).then((h) =>
    Array.from(new Uint8Array(h))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
}

/**
 * @param {object} fields - { itemName, retailer, deadlineKind, dueDateISO, serialNumber, notes }
 */
function buildPassJSON(fields) {
  const { itemName, retailer, deadlineKind, dueDateISO, serialNumber, notes } = fields;
  const dueDate = new Date(dueDateISO);
  const dateLabel = dueDate.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
  const kindLabel = deadlineKind === "warranty" ? "WARRANTY ENDS" : "RETURN WINDOW ENDS";

  return {
    formatVersion: 1,
    passTypeIdentifier: PASS_TYPE_IDENTIFIER,
    teamIdentifier: TEAM_IDENTIFIER,
    organizationName: "Owned",
    serialNumber,
    description: `${itemName} — ${kindLabel.toLowerCase()}`,
    logoText: "Owned",
    generic: {
      primaryFields: [{ key: "item", label: "ITEM", value: itemName }],
      secondaryFields: [
        { key: "deadline", label: kindLabel, value: dateLabel },
        ...(retailer ? [{ key: "retailer", label: "RETAILER", value: retailer }] : []),
      ],
      backFields: [
        { key: "details", label: "Details", value: notes || "Tracked by Owned — your purchase, return and warranty tracker." },
      ],
    },
    relevantDate: dueDate.toISOString(),
    backgroundColor: "rgb(168, 70, 30)",
    foregroundColor: "rgb(250, 248, 243)",
    labelColor: "rgb(250, 248, 243)",
  };
}

/**
 * @param {object} passFields - see buildPassJSON
 * @param {object} assets - { "icon.png": Uint8Array, "icon@2x.png": Uint8Array, ... }
 * @param {Uint8Array} signerCertDER
 * @param {Uint8Array} wwdrCertDER
 * @param {CryptoKey} privateKey
 */
async function buildSignedPass(passFields, assets, signerCertDER, wwdrCertDER, privateKey) {
  const passJSON = buildPassJSON(passFields);
  const passJSONBytes = new TextEncoder().encode(JSON.stringify(passJSON));

  const files = { "pass.json": passJSONBytes, ...assets };

  const manifestEntries = {};
  for (const [name, bytes] of Object.entries(files)) {
    manifestEntries[name] = await sha1Hex(bytes);
  }
  const manifestBytes = new TextEncoder().encode(JSON.stringify(manifestEntries));

  const signature = await signManifestCMS(manifestBytes, signerCertDER, wwdrCertDER, privateKey, new Date());

  return buildZip({
    ...files,
    "manifest.json": manifestBytes,
    signature: new Uint8Array(signature),
  });
}

export { buildPassJSON, buildSignedPass, sha1Hex };
