// Cross-check of the SBTP v1 test vectors against @noble/ed25519.
//
// For every well-formed vector (expect.block_id present), this script:
//   1. parses the block per spec §2 / §2.1 and extracts PubKey (A) and the signature (R ‖ S);
//   2. checks that expect.signed_message_hex is SIG_PREFIX ‖ expect.block_id (spec §3.2, ADR 0002).
//      The block_id itself is taken from the vector: recomputing it needs BLAKE3 derive_key, and no
//      dependency is added for that;
//   3. runs noble's `verifyAsync` in its strict mode ({ zip215: false }) and its default ZIP-215 mode;
//   4. evaluates V1 to V6 (ADR 0003) one by one with noble's `Point` primitives and node:crypto SHA-512,
//      only to name the criterion behind a divergence. This diagnosis shares noble's point arithmetic, so
//      it is not an independent verifier; it is checked against the criteria listed in each vector's
//      description (written by gen_vectors.rs, which does not use noble).
//
// Exit code: 1 if the vectors or the diagnosis are inconsistent (signed message, parsing, criteria
// mismatch, or a valid vector rejected by noble). Divergences of noble from V1-V6 are the expected output
// of this report and do not fail it.
//
// Usage: node check-vectors.mjs [VECTOR_DIR] [--markdown]

import { readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as ed from '@noble/ed25519';

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const markdown = args.includes('--markdown');
const dir = args.find((a) => !a.startsWith('--')) ?? join(here, '..', '..', 'docs', 'test-vectors', 'v1');

// spec §3.2: SIG_PREFIX = "SBTP-v1-block-sig" (17 bytes).
const SIG_PREFIX_HEX = Buffer.from('SBTP-v1-block-sig', 'ascii').toString('hex');
// spec §2: fixed header is 52 bytes, PubKey at 19..51, Parents Count at 51.
const PUBKEY_OFF = 19;
const PARENTS_COUNT_OFF = 51;
const FIXED_HEADER = 52;
const SIG_LEN = 64;
// ADR 0003 V3: L = 2^252 + 27742317777372353535851937790883648493.
const L = (1n << 252n) + 27742317777372353535851937790883648493n;

const hexToBytes = (h) => Uint8Array.from(Buffer.from(h, 'hex'));
const bytesToHex = (b) => Buffer.from(b).toString('hex');
const leToBig = (b) => BigInt('0x' + (bytesToHex(Uint8Array.from(b).reverse()) || '0'));

// Throws on any buffer that is not exactly one well-formed layout; every read is bounds-checked first.
function parseBlock(block) {
  if (block.length < FIXED_HEADER + 2 + SIG_LEN) throw new Error('block shorter than 118 bytes');
  const n = block[PARENTS_COUNT_OFF];
  const lenOff = FIXED_HEADER + 32 * n; // spec §2.1 Offset(Payload Len)
  if (lenOff + 2 > block.length) throw new Error('Payload Len field out of bounds');
  const p = (block[lenOff] << 8) | block[lenOff + 1];
  const sigOff = lenOff + 2 + p; // spec §2.1 Offset(Signature)
  if (sigOff + SIG_LEN !== block.length) throw new Error('block layout does not add up');
  return {
    pubkey: block.subarray(PUBKEY_OFF, PUBKEY_OFF + 32),
    sig: block.subarray(sigOff, sigOff + SIG_LEN),
  };
}

const tryDecode = (bytes, zip215) => {
  try {
    return ed.Point.fromBytes(bytes, zip215);
  } catch {
    return null;
  }
};

// Per-criterion diagnosis. `true` = rejection condition met (criterion fails), `false` = holds,
// `null` = not evaluable. Decoding for V2, V4, V5 and V6 is permissive (ZIP-215 decoding), so that a
// non-canonical encoding is reported by V1 (A) or V6 (R) as in gen_vectors.rs.
function diagnose(pubkey, sig, msg) {
  const r = sig.subarray(0, 32);
  const s = leToBig(sig.subarray(32, 64));
  const aStrict = tryDecode(pubkey, false);
  const a = tryDecode(pubkey, true);
  const rPt = tryDecode(r, true);
  const out = {};
  // V1: canonical RFC 8032 §5.1.3 decoding, plus recompression to the same bytes.
  out.V1 = aStrict === null || bytesToHex(aStrict.toBytes()) !== bytesToHex(pubkey);
  out.V2 = a === null ? null : a.isSmallOrder();
  out.V3 = s >= L;
  out.V4 = rPt === null;
  out.V5 = rPt === null ? null : rPt.isSmallOrder();
  let cofactored = null;
  if (a === null) {
    out.V6 = null;
  } else {
    const k = leToBig(createHash('sha512').update(r).update(pubkey).update(msg).digest()) % L;
    const sB = ed.Point.BASE.multiply(s % L, false);
    const kA = a.multiply(k, false);
    out.V6 = bytesToHex(sB.subtract(kA).toBytes()) !== bytesToHex(r);
    if (rPt !== null) cofactored = rPt.add(kA).subtract(sB).clearCofactor().is0();
  }
  return { criteria: out, cofactored };
}

// "fails V1, V6; holds V2, V3, ..." or "V1 to V6 all hold." from the vector description.
function describedCriteria(description) {
  const m = description.match(/Signature criteria[^:]*:(.*)$/);
  if (!m) return null;
  const text = m[1];
  const res = {};
  if (/V1 to V6 all hold/.test(text)) {
    for (let i = 1; i <= 6; i++) res[`V${i}`] = false;
    return res;
  }
  const grab = (word, value) => {
    const g = text.match(new RegExp(`${word} ((?:V\\d(?:, )?)+)`));
    if (g) for (const c of g[1].split(', ')) res[c.trim()] = value;
  };
  grab('fails', true);
  grab('holds', false);
  for (const c of text.matchAll(/(V\d) not evaluable/g)) res[c[1]] = null;
  return res;
}

const fmt = (b) => (b ? 'accept' : 'reject');
const rows = [];
let inconsistencies = 0;
const files = readdirSync(dir).filter((f) => f.endsWith('.json')).sort();

// Every expect.error that can carry a signature verdict (spec §2.2: R1, C1, C2, C3), and null.
const KIND_OF_ERROR = new Map([
  [null, 'valid'],
  ['BlockIdMismatch', 'R1'],
  ['InsufficientPow', 'C1'],
  ['InvalidPublicKey', 'C2'],
  ['InvalidSignature', 'C3'],
]);
const CRITERIA = ['V1', 'V2', 'V3', 'V4', 'V5', 'V6'];

// Checks one well-formed vector. Returns its row and the list of inconsistencies found.
async function checkVector(v) {
  const problems = [];
  const kind = KIND_OF_ERROR.get(v.expect.error);
  if (kind === undefined) throw new Error(`unknown expect.error ${JSON.stringify(v.expect.error)}`);
  const block = hexToBytes(v.block_hex);
  const { pubkey, sig } = parseBlock(block);
  const msgHex = SIG_PREFIX_HEX + v.expect.block_id;
  if (v.expect.signed_message_hex !== msgHex) problems.push('signed_message_hex is not SIG_PREFIX ‖ block_id');
  const msg = hexToBytes(msgHex);
  const strict = await ed.verifyAsync(sig, msg, pubkey, { zip215: false });
  const zip215 = await ed.verifyAsync(sig, msg, pubkey, { zip215: true });
  const { criteria, cofactored } = diagnose(pubkey, sig, msg);

  // The description must state a verdict for each of V1 to V6.
  const described = describedCriteria(v.description) ?? {};
  for (const c of CRITERIA) {
    if (!(c in described)) problems.push(`description states no verdict for ${c}`);
    else if (criteria[c] !== described[c]) {
      problems.push(`diagnosis ${c}=${criteria[c]} but description says ${described[c]}`);
    }
  }

  // Signature-level verdict under V1-V6 (C2 + C3). For C1/R1 vectors the block is rejected earlier,
  // but the signature itself is valid: that verdict is what noble is compared with.
  const sigOk = !Object.values(criteria).some((x) => x === true);
  if ((kind === 'C2' || kind === 'C3') && sigOk) {
    problems.push(`expected ${v.expect.error} but V1-V6 diagnosis holds`);
  }
  if ((kind === 'valid' || kind === 'C1' || kind === 'R1') && (!sigOk || !strict || !zip215)) {
    problems.push('a valid signature is rejected (diagnosis or noble)');
  }
  const failed = CRITERIA.filter((c) => criteria[c] === true);
  const row = {
    name: v.name,
    kind,
    expected: fmt(sigOk),
    strict: fmt(strict),
    zip215: fmt(zip215),
    failed: failed.join(',') || '-',
    cofactored: cofactored === null ? 'n/a' : cofactored ? 'holds' : 'fails',
  };
  return { row, problems };
}

for (const f of files) {
  let name = f;
  try {
    const v = JSON.parse(readFileSync(join(dir, f), 'utf8'));
    name = v.name ?? f;
    if (v.expect.block_id == null) {
      rows.push({ name, kind: 'format', skipped: true });
      continue;
    }
    const { row, problems } = await checkVector(v);
    rows.push(row);
    for (const p of problems) console.error(`${name}: ${p}`);
    inconsistencies += problems.length;
  } catch (error) {
    console.error(`${name}: ${error.message}`);
    inconsistencies++;
  }
}

const checked = rows.filter((r) => !r.skipped);
const divStrict = checked.filter((r) => r.strict !== r.expected);
const divZip = checked.filter((r) => r.zip215 !== r.expected);

if (markdown) {
  console.log('| Vector | Kind | Fails | Cofactored eq. | Expected | noble strict | noble ZIP-215 |');
  console.log('|---|---|---|---|---|---|---|');
  for (const r of checked) {
    const mark = (x) => (x === r.expected ? x : `**${x}**`);
    console.log(
      `| ${r.name} | ${r.kind} | ${r.failed} | ${r.cofactored} | ${r.expected} | ${mark(r.strict)} | ${mark(r.zip215)} |`,
    );
  }
} else {
  for (const r of checked) {
    const d = (x) => (x === r.expected ? ' ' : '!');
    console.log(
      `${r.name.padEnd(42)} ${r.kind.padEnd(5)} fails=${r.failed.padEnd(9)} cof=${r.cofactored.padEnd(5)} ` +
        `expected=${r.expected} strict=${r.strict}${d(r.strict)} zip215=${r.zip215}${d(r.zip215)}`,
    );
  }
}
console.log('');
console.log(`vectors: ${rows.length}, signature-checked: ${checked.length}, format-only skipped: ${rows.length - checked.length}`);
console.log(`noble strict  divergences: ${divStrict.length} ${divStrict.map((r) => r.name).join(' ')}`);
console.log(`noble ZIP-215 divergences: ${divZip.length} ${divZip.map((r) => r.name).join(' ')}`);
console.log(`inconsistencies: ${inconsistencies}`);
process.exit(inconsistencies === 0 ? 0 : 1);
