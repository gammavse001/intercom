#!/usr/bin/env node
/**
 * ╔══════════════════════════════════════════════════════════╗
 * ║          S H A D O W K E Y   v1.0.0                    ║
 * ║   P2P Shamir's Secret Sharing via Hyperswarm            ║
 * ║   Intercom Vibe Competition                             ║
 * ║   Trac: [INSERT_YOUR_TRAC_ADDRESS_HERE]                 ║
 * ╚══════════════════════════════════════════════════════════╝
 *
 * WHAT IS SHAMIR'S SECRET SHARING?
 *   A cryptographic scheme where a secret is split into N shares.
 *   The secret can only be reconstructed when at least K shares are
 *   combined (K-of-N threshold). Any K-1 shares reveal NOTHING.
 *
 * IMPLEMENTATION:
 *   Pure GF(256) Galois Field arithmetic — same math used in HSMs
 *   and military-grade key management. Zero external crypto deps.
 *
 * MODES:
 *   node index.js                              # Interactive menu
 *   node index.js --mode split                 # Split secret → distribute P2P
 *   node index.js --mode reconstruct           # Collect shares → recover secret
 *   node index.js --n 5 --k 3                  # 5 shares, threshold 3
 *   node index.js --session "vault-2026"       # Named P2P session
 */

'use strict';

const Hyperswarm = require('hyperswarm');
const hcrypto    = require('hypercore-crypto');
const b4a        = require('b4a');
const readline   = require('readline');
const nodeCrypto = require('crypto');
const args       = require('minimist')(process.argv.slice(2));

// ─── ANSI ─────────────────────────────────────────────────────────────────────
const C = {
  reset:'\x1b[0m', bold:'\x1b[1m', dim:'\x1b[2m',
  cyan:'\x1b[36m', green:'\x1b[32m', yellow:'\x1b[33m',
  red:'\x1b[31m',  magenta:'\x1b[35m', white:'\x1b[37m',
};

// ─── Config ───────────────────────────────────────────────────────────────────
const MODE    = args.mode    || null;
const N       = Math.max(2, parseInt(args.n) || 5);
const K       = Math.max(2, Math.min(parseInt(args.k) || 3, N));
const SESSION = args.session || 'default';
const PROTO   = 1;

// ─── Utils ────────────────────────────────────────────────────────────────────
const ts  = () => new Date().toLocaleTimeString('en-GB', { hour12: false });
const log = (icon, col, msg) =>
  process.stdout.write(`${col}${C.bold}[${ts()}]${C.reset} ${col}${icon}${C.reset} ${msg}\n`);
const info    = m => log('ℹ', C.cyan,    m);
const success = m => log('✔', C.green,   m);
const warn    = m => log('⚠', C.yellow,  m);
const danger  = m => log('✖', C.red,     m);

// ─── GF(256) — Galois Field arithmetic ───────────────────────────────────────
// Irreducible polynomial: x^8 + x^4 + x^3 + x^2 + 1 = 0x11d
const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);

;(function buildTables() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 256) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
})();

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[(GF_LOG[a] + GF_LOG[b]) % 255];
}

function gfDiv(a, b) {
  if (b === 0) throw new Error('GF division by zero');
  if (a === 0) return 0;
  return GF_EXP[(GF_LOG[a] - GF_LOG[b] + 255) % 255];
}

function gfPolyEval(poly, x) {
  let r = 0;
  for (let i = poly.length - 1; i >= 0; i--) r = gfMul(r, x) ^ poly[i];
  return r;
}

// ─── Shamir split ─────────────────────────────────────────────────────────────
function shamirSplit(secretBuf, n, k) {
  const shares = Array.from({ length: n }, (_, i) => ({
    x: i + 1,
    y: Buffer.alloc(secretBuf.length),
  }));

  for (let bIdx = 0; bIdx < secretBuf.length; bIdx++) {
    const poly  = new Uint8Array(k);
    poly[0]     = secretBuf[bIdx];
    const rnd   = nodeCrypto.randomBytes(k - 1);
    for (let i = 1; i < k; i++) poly[i] = rnd[i - 1] || 1;

    for (const s of shares) s.y[bIdx] = gfPolyEval(poly, s.x);
  }

  return shares;
}

// ─── Shamir reconstruct (Lagrange interpolation over GF256) ──────────────────
function shamirReconstruct(shares) {
  const len    = shares[0].y.length;
  const result = Buffer.alloc(len);

  for (let bIdx = 0; bIdx < len; bIdx++) {
    let sec = 0;
    for (let i = 0; i < shares.length; i++) {
      let num = 1, den = 1;
      for (let j = 0; j < shares.length; j++) {
        if (i === j) continue;
        num = gfMul(num, shares[j].x);
        den = gfMul(den, shares[i].x ^ shares[j].x);
      }
      sec ^= gfMul(shares[i].y[bIdx], gfDiv(num, den));
    }
    result[bIdx] = sec;
  }

  return result;
}

// ─── Share encoding ───────────────────────────────────────────────────────────
const encodeShare = s => `${s.x.toString(16).padStart(2,'0')}:${s.y.toString('hex')}`;
function decodeShare(str) {
  const [xH, yH] = str.split(':');
  return { x: parseInt(xH, 16), y: Buffer.from(yH, 'hex') };
}

// ─── Banner ───────────────────────────────────────────────────────────────────
function printBanner() {
  console.log(`
${C.magenta}${C.bold}╔══════════════════════════════════════════════════════════╗
║          S H A D O W K E Y   v1.0.0                    ║
║   P2P Shamir's Secret Sharing — K-of-N Threshold        ║
╚══════════════════════════════════════════════════════════╝${C.reset}
  ${C.dim}GF(256) polynomial secret splitting · No server · No trust${C.reset}
  ${C.dim}Intercom Vibe Competition · [INSERT_YOUR_TRAC_ADDRESS_HERE]${C.reset}
`);
}

// ─── SPLIT MODE ───────────────────────────────────────────────────────────────
async function runSplit() {
  const rl  = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = q => new Promise(r => rl.question(q, r));

  console.log(`\n${C.magenta}${C.bold}[ SPLIT MODE ]${C.reset}  ${N} shares · ${K}-of-${N} threshold · session: ${C.bold}${SESSION}${C.reset}\n`);

  const secretStr = (await ask(`${C.yellow}${C.bold}Enter your secret:${C.reset} `)).trim();
  if (!secretStr) { warn('Empty secret — aborting.'); rl.close(); return; }
  rl.close();

  const shares = shamirSplit(Buffer.from(secretStr, 'utf8'), N, K);

  console.log(`\n${C.green}${C.bold}Secret split into ${N} shares (${K}-of-${N} to reconstruct):${C.reset}\n`);
  shares.forEach((s, i) => {
    const enc = encodeShare(s);
    console.log(`  ${C.bold}Share ${i+1}/${N}:${C.reset}`);
    console.log(`  ${C.yellow}${enc}${C.reset}\n`);
  });
  console.log(`${C.dim}Distribute each share to a different peer. Any ${K} of ${N} shares can reconstruct.${C.reset}\n`);

  // Join swarm and deliver shares to first N connecting peers
  info(`Joining P2P session "${SESSION}" — waiting for ${N} peers to receive shares…\n`);

  const seed      = b4a.from(`shadowkey:session:${SESSION}:intercom-vibe-2025`);
  const topic     = hcrypto.hash(seed);
  const peers     = new Set();
  let distributed = 0;
  const swarm     = new Hyperswarm();

  swarm.on('connection', (conn, pi) => {
    const pid = b4a.toString(pi.publicKey, 'hex').slice(0, 10);
    peers.add(conn);

    if (distributed < shares.length) {
      const s   = shares[distributed];
      const msg = JSON.stringify({
        v: PROTO, type: 'share_delivery',
        session: SESSION, shareIndex: s.x,
        totalShares: N, threshold: K,
        share: encodeShare(s),
      });
      try {
        conn.write(b4a.from(msg));
        success(`Share ${s.x}/${N} → peer ${C.dim}(${pid}…)${C.reset}`);
        distributed++;
      } catch (e) { warn(`Send failed: ${e.message}`); }

      if (distributed >= N) {
        success(`All ${N} shares distributed! Session complete.`);
        success(`Secret is now protected by ${K}-of-${N} threshold.`);
      }
    }

    conn.on('data', raw => {
      try {
        const m = JSON.parse(raw.toString());
        if (m.type === 'share_ack') success(`Peer ${C.dim}(${pid}…)${C.reset} confirmed share ${m.shareIndex}.`);
      } catch (_) {}
    });
    conn.on('error', () => {});
    conn.on('close', () => peers.delete(conn));
  });

  swarm.on('error', e => warn(`Swarm: ${e.message}`));
  const disc = swarm.join(topic, { server: true, client: false });
  await disc.flushed();
  info(`Ctrl+C to stop (shares printed above for manual use)\n`);
  process.on('SIGINT', async () => { await swarm.destroy(); process.exit(0); });
}

// ─── RECONSTRUCT MODE ─────────────────────────────────────────────────────────
async function runReconstruct() {
  const myShares = [];
  const peers    = new Set();

  console.log(`\n${C.cyan}${C.bold}[ RECONSTRUCT MODE ]${C.reset}  session: ${C.bold}${SESSION}${C.reset}  need: ${C.bold}${K}${C.reset} shares\n`);

  if (args.share) {
    try {
      const d = decodeShare(String(args.share));
      myShares.push(d);
      info(`Own share loaded (index ${d.x}).`);
    } catch (e) { warn(`Could not parse --share: ${e.message}`); }
  }

  const seed   = b4a.from(`shadowkey:session:${SESSION}:intercom-vibe-2025`);
  const topic  = hcrypto.hash(seed);
  const swarm  = new Hyperswarm();

  const tryReconstruct = () => {
    if (myShares.length >= K) {
      try {
        const buf = shamirReconstruct(myShares.slice(0, K));
        const str = buf.toString('utf8');
        console.log(`\n${C.green}${C.bold}╔══════════════════════════════════════════════╗`);
        console.log(`║     SECRET RECONSTRUCTED SUCCESSFULLY!      ║`);
        console.log(`╚══════════════════════════════════════════════╝${C.reset}`);
        console.log(`\n  ${C.bold}${C.white}${str}${C.reset}\n`);
        console.log(`  ${C.dim}Used ${myShares.length} of ${N} shares (threshold: ${K})${C.reset}\n`);
        swarm.destroy().then(() => process.exit(0));
      } catch (e) { danger(`Reconstruction failed: ${e.message}`); }
    }
  };

  swarm.on('connection', (conn, pi) => {
    const pid = b4a.toString(pi.publicKey, 'hex').slice(0, 10);
    peers.add(conn);
    info(`Peer ${C.dim}(${pid}…)${C.reset} connected  [${myShares.length}/${K} shares]`);

    try {
      conn.write(b4a.from(JSON.stringify({ v: PROTO, type: 'share_request', session: SESSION })));
    } catch (_) {}

    conn.on('data', raw => {
      let m;
      try { m = JSON.parse(raw.toString()); } catch { return; }

      if (m.type === 'share_delivery' && m.session === SESSION) {
        try {
          const d = decodeShare(m.share);
          if (!myShares.find(s => s.x === d.x)) {
            myShares.push(d);
            success(`Share ${d.x}/${m.totalShares} received  [${myShares.length}/${K} needed]`);
            try {
              conn.write(b4a.from(JSON.stringify({ v: PROTO, type: 'share_ack', shareIndex: d.x })));
            } catch (_) {}
            tryReconstruct();
          }
        } catch (e) { warn(`Bad share: ${e.message}`); }
      }
    });
    conn.on('error', () => {});
    conn.on('close', () => peers.delete(conn));
  });

  swarm.on('error', e => warn(`Swarm: ${e.message}`));
  const disc = swarm.join(topic, { server: true, client: true });
  await disc.flushed();
  info(`Listening on session "${SESSION}"… Ctrl+C to cancel.\n`);
  tryReconstruct();
  process.on('SIGINT', async () => { await swarm.destroy(); process.exit(0); });
}

// ─── Interactive menu ─────────────────────────────────────────────────────────
async function interactiveMenu() {
  const rl  = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = q => new Promise(r => rl.question(q, r));

  console.log(`${C.magenta}${C.bold}Choose mode:${C.reset}

  ${C.yellow}[1]${C.reset} split       — Split a secret into ${N} shares (${K}-of-${N})
  ${C.cyan}[2]${C.reset} reconstruct — Collect shares P2P and recover secret
  ${C.dim}[q]${C.reset} quit
`);

  const ch = (await ask(`${C.dim}Choice: ${C.reset}`)).trim().toLowerCase();
  rl.close();

  if      (ch === '1' || ch === 'split')       await runSplit();
  else if (ch === '2' || ch === 'reconstruct') await runReconstruct();
  else { info('Goodbye.'); process.exit(0); }
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  printBanner();
  info(`Config: ${C.bold}${N}${C.reset} shares · ${C.bold}${K}${C.reset}-of-${C.bold}${N}${C.reset} threshold · session: ${C.bold}${SESSION}${C.reset}\n`);

  if      (MODE === 'split')       await runSplit();
  else if (MODE === 'reconstruct') await runReconstruct();
  else                             await interactiveMenu();
}

main().catch(err => { danger(`Fatal: ${err.message}`); process.exit(1); });
