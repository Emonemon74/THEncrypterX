# THEncrypterX Web

A small, standalone browser page that encrypts/decrypts a file entirely
client-side: pick a file, type a password, get an encrypted (or decrypted)
file back as a download. Nothing - not the file, not the password, not any
telemetry - is ever sent anywhere. There is no backend; this is a static
page.

This is the roadmap's optional "Portfolio Differentiator" step
(`../docs/ROADMAP.md`, Phase 16), scoped down deliberately from the
roadmap's full vision - see "Why this isn't the `.thex` format" below.

## Try it

Live at **https://emonemon74.github.io/THEncrypterX/** (deployed
automatically from `main` by `.github/workflows/deploy-pages.yml`
whenever `web/` changes), or run it locally:

```bash
npm install
npm run dev       # http://localhost:5173
```

## Why this isn't the `.thex` format

The desktop/CLI tool (the rest of this repository) uses Argon2id and
XChaCha20-Poly1305, neither of which the browser's native Web Crypto API
implements. Getting real `.thex` compatibility here would mean porting
both via WebAssembly (e.g. `hash-wasm`, `libsodium.js`), reimplementing
the exact chunked wire format in TypeScript, and testing that port against
the same rigor the Python implementation gets (`tests/test_properties.py`,
`tests/test_fuzz_parser.py`, the KAT vector) - a multi-day engineering
effort in its own right, with real risk of subtle incompatibilities in a
security-sensitive format if rushed.

This page takes the smaller, honest alternative instead: a fully working,
fully client-side encryption tool built from **only** native Web Crypto
primitives - zero third-party crypto dependencies, zero WASM, nothing to
audit beyond what's in `src/crypto.ts` and what the browser itself
implements. Files it produces cannot be opened by the CLI/GUI, and vice
versa - it is its own thing, not a compatibility layer.

## Cryptography

| | This page | Desktop/CLI tool |
|---|---|---|
| KDF | PBKDF2-HMAC-SHA256, 600,000 iterations | Argon2id (memory-hard) |
| AEAD | AES-256-GCM | XChaCha20-Poly1305 (default) / AES-256-GCM |
| Nonce | one random 96-bit nonce per file | per-chunk, algorithm-dependent (see main `docs/threat-model.md`) |
| Chunking | none - whole file in memory | streaming, bounded memory |

**PBKDF2, not Argon2id:** Argon2id has no native Web Crypto implementation.
PBKDF2-SHA256 at 600,000 iterations is OWASP's current baseline
recommendation for PBKDF2 specifically - weaker than Argon2id against
GPU/ASIC-parallelized guessing (PBKDF2 isn't memory-hard), but a real,
current, standards-based choice, not a toy. Choose a genuinely strong
password; that matters more here than it does with the CLI's Argon2id.

**One nonce per file is safe here** specifically because each file is
exactly one AEAD message under one freshly-derived key - there is no
multi-message-under-one-key scenario the way the desktop tool's chunked
stream has, which is why *its* AES-256-GCM path needs a counter-nonce
construction and this one doesn't.

**Whole file in memory:** there is no streaming AES-GCM API in Web Crypto,
so encryption/decryption loads the entire file into memory. Fine for
everyday file sizes; not a replacement for the desktop tool on very large
files, which stream in bounded memory regardless of size (see the main
`docs/performance.md`).

## Format (`.thexweb`)

Own tiny format, documented in full in `src/crypto.ts`'s module docstring.
Summary: `magic("TWX1") | version | salt(16) | pbkdf2_iterations(4) |
nonce(12) | filename_len(2) | filename | ciphertext+tag`. Everything before
the ciphertext is authenticated as AES-GCM associated data (not encrypted,
but tamper-evident) - the same "header is its own associated data" pattern
the main `.thex` format uses, reimplemented natively here rather than
copied wholesale.

## Development

```bash
npm run dev       # dev server with HMR
npm run build     # type-check (tsc -b) + production build to dist/
npm test          # vitest - src/crypto.test.ts covers roundtrip, wrong
                   # password, tampered ciphertext/header, malformed input
npm run lint       # oxlint
```

No backend, no server-side code, no deployment pipeline configured here -
`npm run build` produces a static `dist/` deployable to any static host
(GitHub Pages, Netlify, Vercel, etc.) with no server-side requirements.

## Security notes

- This is a demo/portfolio piece, not an audited security product - see
  the comparison table above for exactly what it does differently from
  the desktop tool, and don't assume parity.
- No password-strength checking. Choose a strong, unique password - PBKDF2
  raises the cost per guess, it does not make a weak password safe.
- A lost password means the file is unrecoverable. There is no recovery
  mechanism, by design (a "reset" would mean a backdoor).
- Verify you're really on this page (check the URL/TLS certificate if
  deployed) before entering a password anywhere - this is true of any
  page asking for a password, but doubly so for one whose entire value
  proposition rests on nothing leaving the browser.
