/**
 * Client-side file encryption using only native Web Crypto API primitives -
 * no third-party crypto library, no WASM, nothing loaded over the network
 * beyond this app's own JS bundle. Everything happens in the browser;
 * nothing is ever sent anywhere.
 *
 * This is a standalone format (".thexweb", magic "TWX1"), NOT the same as
 * the desktop/CLI .thex format - see README.md for why (Argon2id and
 * XChaCha20-Poly1305 aren't available as native Web Crypto primitives, and
 * porting them via WASM was a deliberate scope decision this project chose
 * not to take on for a browser demo). Files encrypted here cannot be
 * decrypted by the CLI/GUI, and vice versa.
 *
 * KDF: PBKDF2-HMAC-SHA256, 600,000 iterations (OWASP's current minimum
 * recommendation for PBKDF2-SHA256), not Argon2id - Argon2id has no native
 * Web Crypto implementation.
 *
 * AEAD: AES-256-GCM (native), not XChaCha20-Poly1305 - same reason. A
 * single random 96-bit nonce per file is safe here specifically because
 * each file is exactly one AEAD message under one freshly-derived key,
 * unlike the desktop tool's chunked multi-message stream under one key,
 * which is why AES-GCM there needs the counter-nonce construction
 * documented in the main project's docs/threat-model.md.
 *
 * Whole file loaded into memory - there is no streaming AES-GCM API in Web
 * Crypto, so this is not suitable for very large files the way the
 * desktop tool's chunked I/O is. A browser tab has a few hundred MB to a
 * few GB of usable memory depending on the device; this is a demo, not a
 * replacement for the desktop tool on large files.
 *
 * Format (all integers little-endian):
 *   magic        4 bytes   ASCII "TWX1"
 *   version      1 byte    1
 *   salt         16 bytes  PBKDF2 salt (random)
 *   iterations   4 bytes   u32, PBKDF2 iteration count actually used
 *   nonce        12 bytes  AES-GCM nonce (random)
 *   name_len     2 bytes   u16, length of the filename in bytes
 *   name         name_len  UTF-8 original filename
 *   ciphertext   rest      AES-GCM ciphertext + 16-byte tag
 *
 * Associated data (authenticated, not encrypted): everything from `magic`
 * through `name` - the header is its own associated data, the same pattern
 * the desktop tool's .thex format uses. Tampering with the salt, iteration
 * count, nonce, or filename breaks authentication for the whole file.
 */

const MAGIC = new Uint8Array([0x54, 0x57, 0x58, 0x31]); // "TWX1"
const VERSION = 1;
const SALT_LEN = 16;
const NONCE_LEN = 12;
const PBKDF2_ITERATIONS = 600_000;
const FIXED_HEADER_LEN = MAGIC.length + 1 + SALT_LEN + 4 + NONCE_LEN + 2;

export class FormatError extends Error {}
export class WrongPasswordError extends Error {}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

function u32le(n: number): Uint8Array {
  const buf = new Uint8Array(4);
  new DataView(buf.buffer).setUint32(0, n, true);
  return buf;
}

function u16le(n: number): Uint8Array {
  const buf = new Uint8Array(2);
  new DataView(buf.buffer).setUint16(0, n, true);
  return buf;
}

async function deriveKey(
  password: string,
  salt: Uint8Array,
  iterations: number,
): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt as BufferSource, iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export interface EncryptedFile {
  blob: Blob;
  suggestedName: string;
}

export async function encryptFile(
  file: File | { name: string; arrayBuffer(): Promise<ArrayBuffer> },
  password: string,
): Promise<EncryptedFile> {
  if (password.length === 0) {
    throw new Error("password must not be empty");
  }
  const nameBytes = new TextEncoder().encode(file.name);
  if (nameBytes.length > 0xffff) {
    throw new Error("filename too long");
  }

  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));

  const header = concatBytes(
    MAGIC,
    new Uint8Array([VERSION]),
    salt,
    u32le(PBKDF2_ITERATIONS),
    nonce,
    u16le(nameBytes.length),
    nameBytes,
  );

  const key = await deriveKey(password, salt, PBKDF2_ITERATIONS);
  const plaintext = new Uint8Array(await file.arrayBuffer());
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce as BufferSource, additionalData: header as BufferSource },
      key,
      plaintext as BufferSource,
    ),
  );

  const blob = new Blob([header as BlobPart, ciphertext as BlobPart], {
    type: "application/octet-stream",
  });
  return { blob, suggestedName: `${file.name}.thexweb` };
}

export interface DecryptedFile {
  blob: Blob;
  originalName: string;
}

export async function decryptFile(
  file: File | { arrayBuffer(): Promise<ArrayBuffer> },
  password: string,
): Promise<DecryptedFile> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes.length < FIXED_HEADER_LEN) {
    throw new FormatError("not a .thexweb file (too short)");
  }

  let offset = 0;
  const magic = bytes.subarray(offset, offset + MAGIC.length);
  offset += MAGIC.length;
  if (!magic.every((b, i) => b === MAGIC[i])) {
    throw new FormatError("not a .thexweb file (bad magic bytes)");
  }

  const version = bytes[offset];
  offset += 1;
  if (version !== VERSION) {
    throw new FormatError(`unsupported .thexweb version ${version}`);
  }

  const salt = bytes.subarray(offset, offset + SALT_LEN);
  offset += SALT_LEN;

  const iterations = new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0, true);
  offset += 4;

  const nonce = bytes.subarray(offset, offset + NONCE_LEN);
  offset += NONCE_LEN;

  const nameLen = new DataView(bytes.buffer, bytes.byteOffset + offset, 2).getUint16(0, true);
  offset += 2;

  if (bytes.length < offset + nameLen) {
    throw new FormatError("not a .thexweb file (truncated filename)");
  }
  const nameBytes = bytes.subarray(offset, offset + nameLen);
  offset += nameLen;
  const originalName = new TextDecoder().decode(nameBytes);

  const header = bytes.subarray(0, offset);
  const ciphertext = bytes.subarray(offset);

  const key = await deriveKey(password, salt, iterations);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce as BufferSource, additionalData: header as BufferSource },
      key,
      ciphertext as BufferSource,
    );
  } catch {
    throw new WrongPasswordError("wrong password or corrupted file");
  }

  return {
    blob: new Blob([plaintext]),
    originalName,
  };
}
