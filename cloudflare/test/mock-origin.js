import { createServer } from "node:http";

const port = Number(process.env.PAYLOADSHIELD_ORIGIN_PORT || 8091);
if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
  throw new TypeError("PAYLOADSHIELD_ORIGIN_PORT must be a valid TCP port");
}

const server = createServer((request, response) => {
  const chunks = [];
  let length = 0;
  request.on("data", (chunk) => {
    length += chunk.length;
    if (length > 1024 * 1024) {
      response.writeHead(413).end();
      request.destroy();
      return;
    }
    chunks.push(chunk);
  });
  request.on("end", () => {
    if (response.destroyed) return;
    const result = JSON.stringify({
      method: request.method,
      path: request.url,
      body: Buffer.concat(chunks).toString("utf8"),
    });
    response.writeHead(201, {
      "content-type": "application/json",
      "content-length": Buffer.byteLength(result),
    });
    response.end(result);
  });
});

server.listen(port, "127.0.0.1", () => {
  console.log(`CFPayloadShield test origin listening on http://127.0.0.1:${port}`);
});
