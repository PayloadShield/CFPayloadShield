const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;
const AES_KEY_LENGTH = 32;

export class PayloadSizeError extends RangeError {
  constructor() {
    super("Payload exceeds the configured maximum size");
    this.name = "PayloadSizeError";
  }
}

function webCrypto() {
  if (!globalThis.crypto?.subtle) {
    throw new Error("This runtime does not provide the Web Crypto API");
  }
  return globalThis.crypto;
}

function asBytes(value, name) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  throw new TypeError(`${name} must be a Uint8Array or ArrayBuffer`);
}

function assertPayloadSize(length, config) {
  const maximum = config.maxPayloadSize;
  if (maximum !== undefined
      && (!Number.isSafeInteger(maximum) || maximum < 0)) {
    throw new TypeError("maxPayloadSize must be a non-negative safe integer");
  }
  if (maximum !== undefined && length > maximum) {
    throw new PayloadSizeError();
  }
}

function toBinaryString(bytes) {
  let result = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    result += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return result;
}

export function encodeBase64(value) {
  return btoa(toBinaryString(asBytes(value, "value")));
}

export function decodeBase64(value) {
  if (typeof value !== "string"
      || value.length % 4 !== 0
      || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new TypeError("Invalid standard Base64 value");
  }
  const decoded = atob(value);
  const bytes = Uint8Array.from(decoded, (character) => character.charCodeAt(0));
  if (encodeBase64(bytes) !== value) {
    throw new TypeError("Invalid standard Base64 value");
  }
  return bytes;
}

function assertSymmetricKey(key) {
  const bytes = asBytes(key, "key");
  if (bytes.length !== AES_KEY_LENGTH) {
    throw new TypeError("AES-256 requires a 32-byte key");
  }
  return bytes;
}

function readPem(pem, expectedLabel) {
  if (typeof pem !== "string") {
    throw new TypeError("RSA key must be a PEM string or CryptoKey");
  }
  const match = pem.match(
    new RegExp(`^\\s*-----BEGIN ${expectedLabel}-----([\\s\\S]+?)-----END ${expectedLabel}-----\\s*$`),
  );
  if (!match) {
    throw new TypeError(`RSA key must use the ${expectedLabel} PEM format`);
  }
  return decodeBase64(match[1].replace(/\s/g, ""));
}

function isCryptoKey(value, usage) {
  return value !== null
    && typeof value === "object"
    && value.algorithm?.name === "RSA-OAEP"
    && value.algorithm.modulusLength >= 2048
    && value.usages?.includes(usage);
}

export async function importRsaPublicKey(key) {
  if (isCryptoKey(key, "encrypt")) return key;
  return webCrypto().subtle.importKey(
    "spki",
    readPem(key, "PUBLIC KEY"),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"],
  );
}

export async function importRsaPrivateKey(key) {
  if (isCryptoKey(key, "decrypt")) return key;
  return webCrypto().subtle.importKey(
    "pkcs8",
    readPem(key, "PRIVATE KEY"),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"],
  );
}

async function encryptAesGcm(plaintext, key) {
  const nonce = webCrypto().getRandomValues(new Uint8Array(NONCE_LENGTH));
  const cryptoKey = await webCrypto().subtle.importKey(
    "raw",
    assertSymmetricKey(key),
    "AES-GCM",
    false,
    ["encrypt"],
  );
  const encrypted = new Uint8Array(await webCrypto().subtle.encrypt(
    { name: "AES-GCM", iv: nonce, tagLength: TAG_LENGTH * 8 },
    cryptoKey,
    plaintext,
  ));
  const combined = new Uint8Array(nonce.length + encrypted.length);
  combined.set(nonce);
  combined.set(encrypted, nonce.length);
  return encodeBase64(combined);
}

async function decryptAesGcm(ciphertext, key) {
  const combined = decodeBase64(ciphertext);
  if (combined.length < NONCE_LENGTH + TAG_LENGTH) {
    throw new TypeError("AES-GCM ciphertext is too short");
  }
  const nonce = combined.subarray(0, NONCE_LENGTH);
  const encrypted = combined.subarray(NONCE_LENGTH);
  const cryptoKey = await webCrypto().subtle.importKey(
    "raw",
    assertSymmetricKey(key),
    "AES-GCM",
    false,
    ["decrypt"],
  );
  return new Uint8Array(await webCrypto().subtle.decrypt(
    { name: "AES-GCM", iv: nonce, tagLength: TAG_LENGTH * 8 },
    cryptoKey,
    encrypted,
  ));
}

async function encryptRsaHybrid(plaintext, publicKey) {
  const rsaKey = await importRsaPublicKey(publicKey);
  const aesKey = webCrypto().getRandomValues(new Uint8Array(AES_KEY_LENGTH));
  try {
    const nonce = webCrypto().getRandomValues(new Uint8Array(NONCE_LENGTH));
    const aesCryptoKey = await webCrypto().subtle.importKey(
      "raw",
      aesKey,
      "AES-GCM",
      false,
      ["encrypt"],
    );
    const data = new Uint8Array(await webCrypto().subtle.encrypt(
      { name: "AES-GCM", iv: nonce, tagLength: TAG_LENGTH * 8 },
      aesCryptoKey,
      plaintext,
    ));
    const wrappedKey = new Uint8Array(await webCrypto().subtle.encrypt(
      { name: "RSA-OAEP" },
      rsaKey,
      aesKey,
    ));
    const bundle = JSON.stringify({
      key: encodeBase64(wrappedKey),
      nonce: encodeBase64(nonce),
      data: encodeBase64(data),
    });
    return encodeBase64(new TextEncoder().encode(bundle));
  } finally {
    aesKey.fill(0);
  }
}

async function decryptRsaHybrid(ciphertext, privateKey) {
  const rsaKey = await importRsaPrivateKey(privateKey);
  const bundleBytes = decodeBase64(ciphertext);
  let bundle;
  try {
    bundle = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bundleBytes));
  } catch {
    throw new TypeError("Invalid RSA-Hybrid payload");
  }
  if (bundle === null
      || typeof bundle !== "object"
      || Array.isArray(bundle)
      || Object.keys(bundle).length !== 3
      || typeof bundle.key !== "string"
      || typeof bundle.nonce !== "string"
      || typeof bundle.data !== "string") {
    throw new TypeError("Invalid RSA-Hybrid payload");
  }
  const wrappedKey = decodeBase64(bundle.key);
  const nonce = decodeBase64(bundle.nonce);
  const data = decodeBase64(bundle.data);
  if (nonce.length !== NONCE_LENGTH || data.length < TAG_LENGTH) {
    throw new TypeError("Invalid RSA-Hybrid payload");
  }
  const rawKey = new Uint8Array(await webCrypto().subtle.decrypt(
    { name: "RSA-OAEP" },
    rsaKey,
    wrappedKey,
  ));
  if (rawKey.length !== AES_KEY_LENGTH) {
    rawKey.fill(0);
    throw new TypeError("Invalid RSA-Hybrid payload");
  }
  try {
    const aesKey = await webCrypto().subtle.importKey(
      "raw",
      rawKey,
      "AES-GCM",
      false,
      ["decrypt"],
    );
    return new Uint8Array(await webCrypto().subtle.decrypt(
      { name: "AES-GCM", iv: nonce, tagLength: TAG_LENGTH * 8 },
      aesKey,
      data,
    ));
  } finally {
    rawKey.fill(0);
  }
}

export async function encryptBytes(plaintext, config) {
  const bytes = asBytes(plaintext, "plaintext");
  assertPayloadSize(bytes.length, config);
  if (config?.algorithm === "aes-gcm-256") {
    return encryptAesGcm(bytes, config.key);
  }
  if (config?.algorithm === "rsa-hybrid") {
    return encryptRsaHybrid(bytes, config.publicKey);
  }
  throw new TypeError(`Unsupported PayloadShield algorithm: ${config?.algorithm}`);
}

export async function decryptBytes(ciphertext, config) {
  if (typeof ciphertext !== "string") {
    throw new TypeError("ciphertext must be a Base64 string");
  }
  let plaintext;
  if (config?.algorithm === "aes-gcm-256") {
    plaintext = await decryptAesGcm(ciphertext, config.key);
  } else if (config?.algorithm === "rsa-hybrid") {
    plaintext = await decryptRsaHybrid(ciphertext, config.privateKey);
  } else {
    throw new TypeError(`Unsupported PayloadShield algorithm: ${config?.algorithm}`);
  }
  assertPayloadSize(plaintext.length, config);
  return plaintext;
}

export async function encryptPayload(plaintext, config) {
  return new TextEncoder().encode(JSON.stringify({
    encrypted: await encryptBytes(plaintext, config),
  }));
}

export async function decryptPayload(envelope, config) {
  const bytes = asBytes(envelope, "envelope");
  let parsed;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new TypeError("Invalid PayloadShield JSON envelope");
  }
  if (parsed === null
      || typeof parsed !== "object"
      || Array.isArray(parsed)
      || Object.keys(parsed).length !== 1
      || typeof parsed.encrypted !== "string"
      || parsed.encrypted.length === 0) {
    throw new TypeError("Invalid PayloadShield JSON envelope");
  }
  return decryptBytes(parsed.encrypted, config);
}
