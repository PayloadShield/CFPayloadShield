import {
  PayloadSizeError,
  decodeBase64,
  decryptPayload,
  encryptPayload,
  importRsaPrivateKey,
  importRsaPublicKey,
} from "../../packages/payloadshield-crypto/src/index.js";

const DEFAULT_MAX_BODY_SIZE = 10 * 1024 * 1024;

class BodyTooLargeError extends Error {}

function positiveInteger(value, fallback) {
  if (value === undefined || value === "") return fallback;
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number <= 0) {
    throw new TypeError("PAYLOADSHIELD_MAX_BODY_SIZE must be a positive integer");
  }
  return number;
}

function maximumEnvelopeSize(maxPayloadSize, algorithm) {
  if (algorithm === "rsa-hybrid") {
    const innerBase64Limit = 4 * Math.ceil(maxPayloadSize / 3);
    return 4 * Math.ceil((innerBase64Limit + 2048) / 3) + 128;
  }
  return 4 * Math.ceil(maxPayloadSize / 3) + 64;
}

async function readLimitedBody(stream, maximum) {
  if (stream === null) return new Uint8Array();
  const reader = stream.getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maximum) {
        await reader.cancel();
        throw new BodyTooLargeError();
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const result = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

async function cryptoConfig(env, maxPayloadSize) {
  const algorithm = env.PAYLOADSHIELD_ALGORITHM || "aes-gcm-256";
  if (algorithm === "aes-gcm-256") {
    if (!env.PAYLOADSHIELD_KEY_B64) {
      throw new TypeError("PAYLOADSHIELD_KEY_B64 is required");
    }
    const key = decodeBase64(env.PAYLOADSHIELD_KEY_B64);
    if (key.length !== 32) {
      throw new TypeError("PAYLOADSHIELD_KEY_B64 must decode to exactly 32 bytes");
    }
    return { algorithm, key, maxPayloadSize };
  }
  if (algorithm === "rsa-hybrid") {
    if (!env.PAYLOADSHIELD_PRIVATE_KEY_PEM || !env.PAYLOADSHIELD_PUBLIC_KEY_PEM) {
      throw new TypeError("Both RSA-Hybrid PEM secrets are required");
    }
    return {
      algorithm,
      privateKey: await importRsaPrivateKey(env.PAYLOADSHIELD_PRIVATE_KEY_PEM),
      publicKey: await importRsaPublicKey(env.PAYLOADSHIELD_PUBLIC_KEY_PEM),
      maxPayloadSize,
    };
  }
  throw new TypeError(`Unsupported Cloudflare algorithm: ${algorithm}`);
}

function errorResponse(status, message) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function hasIdentityEncoding(headers) {
  const encoding = headers.get("content-encoding");
  return encoding === null || encoding.toLowerCase() === "identity";
}

function getOriginUrl(requestUrl, origin) {
  const incoming = new URL(requestUrl);
  const destination = new URL(origin);
  if (destination.protocol !== "https:" && destination.protocol !== "http:") {
    throw new TypeError("ORIGIN_URL must use HTTP or HTTPS");
  }
  destination.pathname = `${destination.pathname.replace(/\/+$/, "")}${incoming.pathname}`;
  destination.search = incoming.search;
  destination.hash = "";
  return destination;
}

export default {
  async fetch(request, env) {
    let destination;
    let maxPayloadSize;
    let algorithm;
    let config;
    try {
      if (!env.ORIGIN_URL) throw new TypeError("ORIGIN_URL is required");
      destination = getOriginUrl(request.url, env.ORIGIN_URL);
      maxPayloadSize = positiveInteger(
        env.PAYLOADSHIELD_MAX_BODY_SIZE,
        DEFAULT_MAX_BODY_SIZE,
      );
      algorithm = env.PAYLOADSHIELD_ALGORITHM || "aes-gcm-256";
      if (!["aes-gcm-256", "rsa-hybrid"].includes(algorithm)) {
        throw new TypeError(`Unsupported Cloudflare algorithm: ${algorithm}`);
      }
      config = await cryptoConfig(env, maxPayloadSize);
    } catch {
      return errorResponse(500, "PayloadShield is not configured correctly");
    }

    if (!hasIdentityEncoding(request.headers)) {
      return errorResponse(415, "Compressed PayloadShield requests are not supported");
    }

    let encryptedRequest;
    try {
      encryptedRequest = await readLimitedBody(
        request.body,
        maximumEnvelopeSize(maxPayloadSize, algorithm),
      );
    } catch (error) {
      if (error instanceof BodyTooLargeError) {
        return errorResponse(413, "PayloadShield request is too large");
      }
      return errorResponse(400, "Invalid PayloadShield request");
    }

    let plaintext = encryptedRequest;
    if (encryptedRequest.byteLength !== 0) {
      try {
        plaintext = await decryptPayload(encryptedRequest, config);
      } catch (error) {
        if (error instanceof PayloadSizeError) {
          return errorResponse(413, "PayloadShield request is too large");
        }
        return errorResponse(400, "Invalid PayloadShield request");
      }
    }

    const bodylessMethod = request.method === "GET" || request.method === "HEAD";
    if (bodylessMethod && plaintext.byteLength !== 0) {
      return errorResponse(400, "Payload bodies are not supported with this method");
    }

    const headers = new Headers(request.headers);
    for (const name of [
      "content-length",
      "transfer-encoding",
      "connection",
      "host",
      "content-encoding",
    ]) {
      headers.delete(name);
    }

    let upstreamResponse;
    try {
      upstreamResponse = await fetch(destination, {
        method: request.method,
        headers,
        body: bodylessMethod ? undefined : plaintext,
        redirect: "manual",
      });
    } catch {
      return errorResponse(502, "PayloadShield upstream request failed");
    }

    if (request.method === "HEAD"
        || [204, 205, 304].includes(upstreamResponse.status)
        || upstreamResponse.body === null) {
      return upstreamResponse;
    }
    if (!hasIdentityEncoding(upstreamResponse.headers)) {
      return errorResponse(502, "Compressed upstream responses are not supported");
    }

    let responseBody;
    try {
      responseBody = await readLimitedBody(upstreamResponse.body, maxPayloadSize);
    } catch (error) {
      if (error instanceof BodyTooLargeError) {
        return errorResponse(502, "PayloadShield upstream response is too large");
      }
      return errorResponse(502, "PayloadShield upstream response could not be read");
    }

    let encryptedResponse;
    try {
      encryptedResponse = await encryptPayload(responseBody, config);
    } catch {
      return errorResponse(502, "PayloadShield could not protect the upstream response");
    }

    const responseHeaders = new Headers(upstreamResponse.headers);
    for (const name of [
      "content-length",
      "content-encoding",
      "content-range",
      "accept-ranges",
      "etag",
      "last-modified",
    ]) {
      responseHeaders.delete(name);
    }
    responseHeaders.set("content-type", "application/json");
    responseHeaders.set("cache-control", "no-store");
    return new Response(encryptedResponse, {
      status: upstreamResponse.status,
      statusText: upstreamResponse.statusText,
      headers: responseHeaders,
    });
  },
};
