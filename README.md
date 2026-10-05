# CFPayloadShield

CFPayloadShield is a Cloudflare Wrangler Worker that decrypts PayloadShield
requests before proxying them to your origin and encrypts upstream responses
before returning them to clients. Its standalone JavaScript crypto module uses
the Web Crypto API and can also be used in supported npm frameworks.

## Protocol compatibility

The Worker uses the existing PayloadShield envelope:

```json
{"encrypted":"<standard Base64 ciphertext>"}
```

- `aes-gcm-256`: Base64 of `12-byte nonce || ciphertext || 16-byte tag`.
- `rsa-hybrid`: Base64 of a JSON bundle containing Base64 `key`, `nonce`, and
  `data`. `key` is a random 32-byte AES key wrapped with RSA-OAEP/SHA-256;
  `data` is AES-256-GCM ciphertext followed by its tag.

The plaintext is bytes supplied by the caller; for JSON APIs, serialize and
parse JSON in your application. The Worker supports `aes-gcm-256` and
`rsa-hybrid`. It rejects `chacha20-poly1305` because Cloudflare's Web Crypto API
does not implement that cipher. Crypto failures never fall back to plaintext.

## Install and run

Requires Node.js 22+ and npm for the current Wrangler v4 CLI. The standalone
crypto package itself supports Node.js 20+ and other runtimes with Web Crypto.

```sh
npm install
npm test
```

Set the upstream origin and AES key as Wrangler secrets. The key must be the
standard Base64 encoding of exactly 32 cryptographically random bytes:

```sh
npx wrangler secret put ORIGIN_URL
npx wrangler secret put PAYLOADSHIELD_KEY_B64
npx wrangler dev
```

Generate a key value locally with PowerShell, then paste the output at the
secret prompt:

```powershell
[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
```

For a local round-trip smoke test, put the values in `.dev.vars` (ignored by
git), start a local plaintext echo origin on port 8091, run `npm run dev`, then
run this from another terminal:

```sh
$env:PAYLOADSHIELD_KEY_B64 = "the-same-base64-key-from-dev.vars"
npm run test:local
```

The local smoke test posts an encrypted sample payload to Wrangler's local
Worker and checks that the origin receives plaintext and that the client can
decrypt the encrypted response. Set `PAYLOADSHIELD_LOCAL_URL` to target a
different local Worker URL.

`wrangler.toml` selects the Worker entry point, AES-GCM algorithm, and default
10 MiB plaintext limit. The Worker appends the incoming path and query string
to `ORIGIN_URL`. Use an HTTPS origin for production.

To deploy:

```sh
npx wrangler deploy
```

For RSA-Hybrid, change `PAYLOADSHIELD_ALGORITHM` in `wrangler.toml` to
`rsa-hybrid`, then add the role-specific keys as Wrangler secrets:

```sh
npx wrangler secret put PAYLOADSHIELD_PRIVATE_KEY_PEM
npx wrangler secret put PAYLOADSHIELD_PUBLIC_KEY_PEM
```

The private key must be unencrypted PKCS#8 PEM (`BEGIN PRIVATE KEY`) and
decrypt client requests. The public key must be SubjectPublicKeyInfo PEM
(`BEGIN PUBLIC KEY`) and encrypt responses for the client. RSA keys must be at
least 2048 bits. These keys have different roles and normally belong to
different key pairs. Do not put secret key contents in `wrangler.toml`, source
control, or logs.

## Reusable crypto package

The workspace package at `packages/payloadshield-crypto` has no runtime
dependencies and exports `encryptBytes`, `decryptBytes`, `encryptPayload`,
`decryptPayload`, `encodeBase64`, and `decodeBase64`. Import it as
`@payloadshield/crypto` from this npm workspace, or publish/install that package
to use it in another project.

```js
import { decryptPayload, encryptPayload } from "@payloadshield/crypto";

const key = new Uint8Array(32); // Replace with a securely generated, shared key.
const config = { algorithm: "aes-gcm-256", key };
const plaintext = new TextEncoder().encode(JSON.stringify({ message: "hello" }));
const envelope = await encryptPayload(plaintext, config);
const recovered = await decryptPayload(envelope, config);
```

The functions accept bytes so the package does not assume a framework or
serialization format. For RSA-Hybrid, use a Web Crypto `CryptoKey` or provide a
PKCS#8 private PEM for `decryptPayload` and an SPKI public PEM for
`encryptPayload`. Set `maxPayloadSize` on the config to enforce an application
specific plaintext limit.

## Security and deployment notes

- Payload protection does not replace HTTPS. Use TLS from clients to Cloudflare
  and from Cloudflare to the origin.
- The Worker buffers each body in memory within the configured limit. Choose a
  limit suitable for Cloudflare's request limits and your response workloads.
- Encrypted responses are marked `Cache-Control: no-store` to avoid caching
  ciphertext that is tied to a particular key or request.
- The AES-GCM key is shared by both directions. RSA-Hybrid uses the server
  private key for request decryption and the configured client-recipient public
  key for response encryption.
- This prototype does not add client identity, replay prevention, request
  signing, automatic key rotation, or per-client key selection. Configure
  origin access controls and rotate keys deliberately.
- Configure a lower maximum where possible. `PAYLOADSHIELD_MAX_BODY_SIZE` is a
  positive number of plaintext bytes.

See [Step.md](./Step.md) for the implementation steps and the reason behind
each major choice.
