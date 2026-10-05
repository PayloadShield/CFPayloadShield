# CFPayloadShield implementation steps

This file records what was implemented and why, so the design and learning
decisions can be reviewed alongside the code.

## 1. Inspect the existing project and protocol

- Inspected the target project's README and license. It did not yet contain a
  Worker, npm module, or tests.
- Compared the requested behavior with the existing PayloadShield protocol:
  requests use `{"encrypted":"<standard Base64>"}`; AES-GCM uses
  `12-byte nonce || ciphertext || 16-byte tag`; RSA-Hybrid wraps a random
  32-byte AES key with RSA-OAEP/SHA-256 and carries Base64 `key`, `nonce`, and
  `data` fields in an outer Base64 JSON bundle.
- Reason: preserving that wire format lets existing PayloadShield clients
  communicate with the Worker without a new protocol.

## 2. Create the reusable crypto package

- Added `packages/payloadshield-crypto` as a standalone ES module.
- Used the Web Crypto API for AES-256-GCM and RSA-OAEP/SHA-256. Added strict
  standard-Base64 handling, PKCS#8 private/SPKI public PEM import helpers,
  envelope helpers, and plaintext size checks.
- Kept all Cloudflare bindings and HTTP routing outside the package.
- Reason: framework-independent Web Crypto keeps runtime dependencies at zero
  and makes the crypto helpers usable from npm frameworks that support Web
  Crypto.

## 3. Implement the Cloudflare Worker proxy

- Added `cloudflare/src/index.js` and selected it as the Wrangler entry point.
- The Worker bounds and decrypts request bodies, forwards plaintext to the
  configured origin, bounds the plaintext response, and returns an encrypted
  PayloadShield JSON envelope.
- Preserves the upstream response status and removes representation headers
  that are no longer valid after encryption. Handles bodyless `HEAD`, `204`,
  `205`, and `304` responses, and marks encrypted responses `no-store`.
- Rejects compressed request/response bodies and returns generic errors rather
  than falling back to plaintext.
- Reason: these rules mirror the Nginx gateway's decrypt-proxy-encrypt flow,
  avoid leaking cryptographic diagnostics, and keep the encrypted HTTP
  representation internally consistent.

## 4. Make algorithm and deployment choices explicit

- Configured AES-GCM and a default 10 MiB plaintext limit in `wrangler.toml`.
- Kept deployment-specific origin and keys out of tracked config; Wrangler
  secrets are used for them.
- Supported `aes-gcm-256` and `rsa-hybrid`. Rejected
  `chacha20-poly1305`, since Cloudflare Web Crypto does not expose that cipher.
- RSA-Hybrid accepts a PKCS#8 `BEGIN PRIVATE KEY` for request decryption and a
  SubjectPublicKeyInfo `BEGIN PUBLIC KEY` for response encryption.
- Reason: do not silently substitute algorithms, embed production keys, or
  make fail-open behavior possible after a cryptographic error.

## 5. Add focused test coverage

- Added Node's built-in test-runner tests for AES-GCM layout and round-trip,
  envelope shape, tampering, size limits, canonical Base64 validation, and
  RSA-Hybrid round-trip.
- Added Worker tests verifying plaintext reaches the mocked origin and the
  response is encrypted, plus malformed-request and unsupported-algorithm
  cases.
- Added `npm run test:local` for a real Wrangler-to-origin-to-client local
  encrypted smoke test.
- Reason: checking both the crypto API and adapter tests the end-to-end contract
  rather than only syntax or file presence.

## 6. Document use and deployment

- Added npm scripts for tests, Wrangler development, and deployment.
- Expanded README with environment setup, secret names, interoperable payload
  format, package usage, and important limits/security notes.
- Reason: deployment steps and API examples should be discoverable without
  reading the implementation first.

## 7. Verify the implementation

- Run `npm test` from the repository root.
- Run `npx wrangler deploy --dry-run` to verify Wrangler can bundle the Worker
  and its local crypto-module import.
- Run `npm audit --omit=dev` to check the production dependency tree; the
  crypto package has no runtime dependencies.
- Test against the real origin and intended PayloadShield client before
  deploying production traffic. Keep HTTPS enabled between client, Cloudflare,
  and origin.
