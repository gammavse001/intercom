# ShadowKey — SKILL.md

> Intercom Vibe Competition submission.

## What

P2P Shamir's Secret Sharing via GF(256) Galois Field arithmetic. Splits a secret into N shares using random polynomials of degree K-1. Reconstructs only when K shares combine via Lagrange interpolation. Share delivery over Hyperswarm P2P.

## Modes

| Mode | Flag |
|---|---|
| Interactive | *(none)* — menu |
| Split | `--mode split` |
| Reconstruct | `--mode reconstruct` |

## Parameters: `--n` (total shares) · `--k` (threshold) · `--session` (topic key) · `--share` (own encoded share)

## Algorithm

```
Split:
  poly[0] = secret_byte; poly[1..k-1] = random
  share_i.y[byte] = gfPolyEval(poly, i)  over GF(256)

Reconstruct:
  secret[byte] = Σ share_i.y[byte] × Lagrange_i(0)  over GF(256)
```

## Share Format: `"XX:YYYY..."` — 2-digit hex index + hex payload

## Protocol

```json
{ "v":1, "type":"share_delivery", "session":"...", "shareIndex":1, "totalShares":5, "threshold":3, "share":"01:..." }
{ "v":1, "type":"share_ack",      "shareIndex":1 }
{ "v":1, "type":"share_request",  "session":"..." }
```

## Topic: `hcrypto.hash(b4a.from('shadowkey:session:' + SESSION + ':intercom-vibe-2025'))`

## Trac: `[INSERT_YOUR_TRAC_ADDRESS_HERE]`
## License: MIT
