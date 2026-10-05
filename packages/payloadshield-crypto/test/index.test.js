import assert from "node:assert/strict";
import { test } from "node:test";
import { webcrypto } from "node:crypto";

import {
  PayloadSizeError,
  decodeBase64,
  decryptBytes,
  decryptPayload,
  encodeBase64,
  encryptBytes,
  encryptPayload,
  importRsaPrivateKey,
  importRsaPublicKey,
} from "../src/index.js";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const key = Uint8Array.from({ length: 32 }, (_, index) => index);

test("uses the shared AES-GCM nonce || ciphertext || tag format", async () => {
  const config = { algorithm: "aes-gcm-256", key };
  const plaintext = new TextEncoder().encode('{"value":42}');
  const ciphertext = await encryptBytes(plaintext, config);
  assert.equal(decodeBase64(ciphertext).length, 12 + plaintext.length + 16);
  assert.deepEqual(await decryptBytes(ciphertext, config), plaintext);
  assert.deepEqual(decodeBase64(encodeBase64(plaintext)), plaintext);
});

test("wraps bytes in the shared encrypted JSON envelope", async () => {
  const config = { algorithm: "aes-gcm-256", key };
  const plaintext = new TextEncoder().encode("round trip");
  assert.deepEqual(
    await decryptPayload(await encryptPayload(plaintext, config), config),
    plaintext,
  );
});

test("rejects modified ciphertext and enforces plaintext size limits", async () => {
  const config = { algorithm: "aes-gcm-256", key };
  const ciphertext = await encryptBytes(new TextEncoder().encode("secret"), config);
  const bytes = decodeBase64(ciphertext);
  bytes[bytes.length - 1] ^= 1;
  await assert.rejects(decryptBytes(encodeBase64(bytes), config));
  await assert.rejects(
    encryptBytes(new Uint8Array(2), { ...config, maxPayloadSize: 1 }),
    PayloadSizeError,
  );
});

test("encrypts and decrypts the interoperable RSA-Hybrid bundle", async () => {
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"],
  );
  const publicDer = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  const privateDer = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const publicPem = `-----BEGIN PUBLIC KEY-----\n${encodeBase64(publicDer)}\n-----END PUBLIC KEY-----`;
  const privatePem = `-----BEGIN PRIVATE KEY-----\n${encodeBase64(privateDer)}\n-----END PRIVATE KEY-----`;
  const config = {
    algorithm: "rsa-hybrid",
    publicKey: await importRsaPublicKey(publicPem),
    privateKey: await importRsaPrivateKey(privatePem),
  };
  const plaintext = new TextEncoder().encode("hybrid payload");
  const ciphertext = await encryptBytes(plaintext, config);
  const bundle = JSON.parse(new TextDecoder().decode(decodeBase64(ciphertext)));
  assert.deepEqual(Object.keys(bundle).sort(), ["data", "key", "nonce"]);
  assert.deepEqual(await decryptBytes(ciphertext, config), plaintext);
});

test("rejects non-canonical Base64 and extra envelope properties", async () => {
  assert.throws(() => decodeBase64("a==="), TypeError);
  await assert.rejects(
    decryptPayload(
      new TextEncoder().encode('{"encrypted":"AAAA","extra":true}'),
      { algorithm: "aes-gcm-256", key },
    ),
    TypeError,
  );
});
