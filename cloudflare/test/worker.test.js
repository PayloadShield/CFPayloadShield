import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { webcrypto } from "node:crypto";

import worker from "../src/index.js";
import {
  decryptPayload,
  encryptPayload,
} from "../../packages/payloadshield-crypto/src/index.js";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const key = Uint8Array.from({ length: 32 }, (_, index) => index);
const config = { algorithm: "aes-gcm-256", key };
const originalFetch = globalThis.fetch;

before(() => {
  globalThis.fetch = async (url, init) => new Response(
    JSON.stringify({
      url: url.toString(),
      method: init.method,
      body: init.body ? new TextDecoder().decode(init.body) : "",
    }),
    { status: 201, headers: { "content-type": "application/json" } },
  );
});

after(() => {
  globalThis.fetch = originalFetch;
});

test("decrypts, proxies plaintext, and encrypts the response", async () => {
  const body = new TextEncoder().encode(JSON.stringify({ message: "hello" }));
  const envelope = await encryptPayload(body, config);
  const response = await worker.fetch(
    new Request("https://shield.example/api/items?q=one", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: envelope,
    }),
    {
      ORIGIN_URL: "https://origin.example/base",
      PAYLOADSHIELD_KEY_B64: btoa(String.fromCharCode(...key)),
    },
  );

  assert.equal(response.status, 201);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const result = await decryptPayload(
    new Uint8Array(await response.arrayBuffer()),
    config,
  );
  const proxied = JSON.parse(new TextDecoder().decode(result));
  assert.equal(proxied.url, "https://origin.example/base/api/items?q=one");
  assert.equal(proxied.method, "POST");
  assert.equal(proxied.body, '{"message":"hello"}');
});

test("rejects malformed envelopes", async () => {
  const response = await worker.fetch(
    new Request("https://shield.example/api", {
      method: "POST",
      body: '{"encrypted":"not-valid"}',
    }),
    {
      ORIGIN_URL: "https://origin.example",
      PAYLOADSHIELD_KEY_B64: btoa(String.fromCharCode(...key)),
    },
  );
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: "Invalid PayloadShield request" });
});

test("rejects unsupported ChaCha configuration", async () => {
  const response = await worker.fetch(
    new Request("https://shield.example/api"),
    {
      ORIGIN_URL: "https://origin.example",
      PAYLOADSHIELD_ALGORITHM: "chacha20-poly1305",
    },
  );
  assert.equal(response.status, 500);
});

test("rejects plaintext request bodies over the configured limit", async () => {
  const envelope = await encryptPayload(new TextEncoder().encode("123456789"), config);
  const response = await worker.fetch(
    new Request("https://shield.example/api", {
      method: "POST",
      body: envelope,
    }),
    {
      ORIGIN_URL: "https://origin.example",
      PAYLOADSHIELD_KEY_B64: btoa(String.fromCharCode(...key)),
      PAYLOADSHIELD_MAX_BODY_SIZE: "8",
    },
  );
  assert.equal(response.status, 413);
  assert.deepEqual(await response.json(), { error: "PayloadShield request is too large" });
});
