import assert from "node:assert/strict";

import {
  decryptPayload,
  encryptPayload,
} from "../../packages/payloadshield-crypto/src/index.js";

const keyBase64 = process.env.PAYLOADSHIELD_KEY_B64;
if (!keyBase64) {
  throw new Error("Set PAYLOADSHIELD_KEY_B64 to run the local Worker smoke test");
}

const key = Uint8Array.from(atob(keyBase64), (character) => character.charCodeAt(0));
if (key.length !== 32) {
  throw new Error("PAYLOADSHIELD_KEY_B64 must decode to exactly 32 bytes");
}

const endpoint = process.env.PAYLOADSHIELD_LOCAL_URL || "http://127.0.0.1:8787";
const config = { algorithm: "aes-gcm-256", key };
const plaintext = new TextEncoder().encode(
  JSON.stringify({ message: "local smoke test" }),
);
const encryptedRequest = await encryptPayload(plaintext, config);
const response = await fetch(new URL("/api/check?run=local", endpoint), {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: encryptedRequest,
});

assert.equal(response.status, 201, "upstream status should be preserved");
assert.equal(
  response.headers.get("cache-control"),
  "no-store",
  "encrypted responses should not be cached",
);

const decryptedResponse = await decryptPayload(
  new Uint8Array(await response.arrayBuffer()),
  config,
);
const upstream = JSON.parse(new TextDecoder().decode(decryptedResponse));
assert.equal(upstream.method, "POST");
assert.equal(upstream.path, "/api/check?run=local");
assert.deepEqual(JSON.parse(upstream.body), { message: "local smoke test" });

console.log("PASS: Worker decrypted the request before proxying it.");
console.log("PASS: Mock origin received the expected plaintext and URL.");
console.log("PASS: Worker encrypted the upstream response for the client.");
