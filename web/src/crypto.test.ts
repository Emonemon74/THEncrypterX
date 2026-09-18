import { describe, expect, it } from "vitest";
import { decryptFile, encryptFile, FormatError, WrongPasswordError } from "./crypto";

function makeFile(name: string, content: string | Uint8Array): File {
  return new File([content as BlobPart], name);
}

async function bytesOf(blob: Blob): Promise<Uint8Array> {
  return new Uint8Array(await blob.arrayBuffer());
}

describe("encryptFile / decryptFile roundtrip", () => {
  it("recovers the original content and filename", async () => {
    const src = makeFile("report.txt", "some secret contents");
    const encrypted = await encryptFile(src, "correct horse battery staple");

    const encryptedFile = new File([encrypted.blob], encrypted.suggestedName);
    const decrypted = await decryptFile(encryptedFile, "correct horse battery staple");

    expect(decrypted.originalName).toBe("report.txt");
    expect(new TextDecoder().decode(await bytesOf(decrypted.blob))).toBe(
      "some secret contents",
    );
  });

  it("round-trips an empty file", async () => {
    const src = makeFile("empty.bin", new Uint8Array(0));
    const encrypted = await encryptFile(src, "pw");
    const decrypted = await decryptFile(
      new File([encrypted.blob], "x"),
      "pw",
    );
    expect((await bytesOf(decrypted.blob)).length).toBe(0);
  });

  it("round-trips binary content, not just text", async () => {
    const data = crypto.getRandomValues(new Uint8Array(5000));
    const src = makeFile("data.bin", data);
    const encrypted = await encryptFile(src, "pw");
    const decrypted = await decryptFile(new File([encrypted.blob], "x"), "pw");
    expect(await bytesOf(decrypted.blob)).toEqual(data);
  });

  it("produces different ciphertext each time (fresh salt/nonce)", async () => {
    const src = makeFile("doc.txt", "same content");
    const a = await encryptFile(src, "pw");
    const b = await encryptFile(src, "pw");
    expect(await bytesOf(a.blob)).not.toEqual(await bytesOf(b.blob));
  });

  it("suggests a .thexweb output filename", async () => {
    const src = makeFile("doc.txt", "x");
    const encrypted = await encryptFile(src, "pw");
    expect(encrypted.suggestedName).toBe("doc.txt.thexweb");
  });
});

describe("wrong password / tampering", () => {
  it("rejects the wrong password", async () => {
    const src = makeFile("doc.txt", "secret");
    const encrypted = await encryptFile(src, "right-password");
    const encryptedFile = new File([encrypted.blob], "x");

    await expect(decryptFile(encryptedFile, "wrong-password")).rejects.toThrow(
      WrongPasswordError,
    );
  });

  it("rejects a tampered ciphertext", async () => {
    const src = makeFile("doc.txt", "secret");
    const encrypted = await encryptFile(src, "pw");
    const bytes = await bytesOf(encrypted.blob);
    bytes[bytes.length - 1] ^= 0x01; // flip a bit inside the GCM tag
    const tampered = new File([bytes as BlobPart], "x");

    await expect(decryptFile(tampered, "pw")).rejects.toThrow(WrongPasswordError);
  });

  it("rejects a tampered filename (authenticated as associated data)", async () => {
    const src = makeFile("doc.txt", "secret");
    const encrypted = await encryptFile(src, "pw");
    const bytes = await bytesOf(encrypted.blob);
    // name_len field is right after magic(4)+version(1)+salt(16)+iterations(4)+nonce(12) = 37
    const nameStart = 4 + 1 + 16 + 4 + 12 + 2;
    bytes[nameStart] ^= 0x01; // flip a byte inside the plaintext filename
    const tampered = new File([bytes as BlobPart], "x");

    await expect(decryptFile(tampered, "pw")).rejects.toThrow(WrongPasswordError);
  });
});

describe("malformed input", () => {
  it("rejects a file that is too short to be a header", async () => {
    const bogus = makeFile("x", "short");
    await expect(decryptFile(bogus, "pw")).rejects.toThrow(FormatError);
  });

  it("rejects bad magic bytes", async () => {
    const src = makeFile("doc.txt", "secret");
    const encrypted = await encryptFile(src, "pw");
    const bytes = await bytesOf(encrypted.blob);
    bytes[0] = 0x00;
    const tampered = new File([bytes as BlobPart], "x");

    await expect(decryptFile(tampered, "pw")).rejects.toThrow(FormatError);
  });

  it("rejects an unsupported version", async () => {
    const src = makeFile("doc.txt", "secret");
    const encrypted = await encryptFile(src, "pw");
    const bytes = await bytesOf(encrypted.blob);
    bytes[4] = 99; // version byte
    const tampered = new File([bytes as BlobPart], "x");

    await expect(decryptFile(tampered, "pw")).rejects.toThrow(FormatError);
  });

  it("rejects a truncated filename length claim", async () => {
    const src = makeFile("doc.txt", "secret");
    const encrypted = await encryptFile(src, "pw");
    const bytes = (await bytesOf(encrypted.blob)).slice(0, 4 + 1 + 16 + 4 + 12 + 2 + 3);
    const tampered = new File([bytes as BlobPart], "x");

    await expect(decryptFile(tampered, "pw")).rejects.toThrow(FormatError);
  });
});

describe("input validation", () => {
  it("rejects an empty password on encrypt", async () => {
    const src = makeFile("doc.txt", "secret");
    await expect(encryptFile(src, "")).rejects.toThrow();
  });
});
