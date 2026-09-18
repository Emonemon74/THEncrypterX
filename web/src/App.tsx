import { useEffect, useRef, useState } from "react";
import {
  decryptFile,
  encryptFile,
  FormatError,
  WrongPasswordError,
  type DecryptedFile,
  type EncryptedFile,
} from "./crypto";

type Mode = "encrypt" | "decrypt";
type Result =
  | { mode: "encrypt"; data: EncryptedFile }
  | { mode: "decrypt"; data: DecryptedFile };

function friendlyError(err: unknown): string {
  if (err instanceof WrongPasswordError) {
    return "Wrong password, or this file was tampered with or corrupted.";
  }
  if (err instanceof FormatError) {
    return `Not a valid .thexweb file: ${err.message}`;
  }
  if (err instanceof Error) {
    return err.message;
  }
  return "Something went wrong.";
}

export default function App() {
  const [mode, setMode] = useState<Mode>("encrypt");
  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Result | null>(null);
  const [downloadUrl, setDownloadUrl] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  // Mirrors downloadUrl for cleanup only, updated in an effect (never
  // during render) - the unmount cleanup below needs the *latest* URL
  // without re-running on every change, which is exactly what a ref
  // kept in sync by its own effect is for.
  const downloadUrlRef = useRef<string | null>(null);

  useEffect(() => {
    downloadUrlRef.current = downloadUrl;
  }, [downloadUrl]);

  useEffect(() => {
    return () => {
      if (downloadUrlRef.current) URL.revokeObjectURL(downloadUrlRef.current);
    };
  }, []);

  function resetForNewFile() {
    setResult(null);
    setError(null);
    if (downloadUrl) {
      URL.revokeObjectURL(downloadUrl);
      setDownloadUrl(null);
    }
  }

  function switchMode(next: Mode) {
    setMode(next);
    setFile(null);
    setPassword("");
    setConfirmPassword("");
    resetForNewFile();
  }

  function handleFile(f: File | undefined | null) {
    if (!f) return;
    setFile(f);
    resetForNewFile();
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!file || busy) return;
    if (mode === "encrypt" && password !== confirmPassword) {
      setError("Passwords don't match.");
      return;
    }

    setBusy(true);
    setError(null);
    try {
      if (mode === "encrypt") {
        const data = await encryptFile(file, password);
        setResult({ mode: "encrypt", data });
        setDownloadUrl(URL.createObjectURL(data.blob));
      } else {
        const data = await decryptFile(file, password);
        setResult({ mode: "decrypt", data });
        setDownloadUrl(URL.createObjectURL(data.blob));
      }
    } catch (err) {
      setError(friendlyError(err));
    } finally {
      setBusy(false);
    }
  }

  const downloadName =
    result?.mode === "encrypt"
      ? result.data.suggestedName
      : result?.mode === "decrypt"
        ? result.data.originalName
        : "";

  const canSubmit =
    file !== null &&
    password.length > 0 &&
    !busy &&
    (mode === "decrypt" || password === confirmPassword);

  return (
    <div className="page">
      <header className="header">
        <h1>THEncrypterX Web</h1>
        <p className="tagline">
          Client-side file encryption. Everything happens in this browser tab
          - your file and password are never sent anywhere.
        </p>
      </header>

      <div className="mode-toggle" role="tablist" aria-label="Mode">
        <button
          type="button"
          role="tab"
          aria-selected={mode === "encrypt"}
          className={mode === "encrypt" ? "active" : ""}
          onClick={() => switchMode("encrypt")}
        >
          Encrypt
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={mode === "decrypt"}
          className={mode === "decrypt" ? "active" : ""}
          onClick={() => switchMode("decrypt")}
        >
          Decrypt
        </button>
      </div>

      <form onSubmit={handleSubmit} className="panel">
        <label
          className={`dropzone${dragActive ? " active" : ""}${file ? " has-file" : ""}`}
          onDragOver={(e) => {
            e.preventDefault();
            setDragActive(true);
          }}
          onDragLeave={() => setDragActive(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragActive(false);
            handleFile(e.dataTransfer.files[0]);
          }}
        >
          <input
            ref={fileInputRef}
            type="file"
            onChange={(e) => handleFile(e.target.files?.[0])}
            hidden
          />
          {file ? (
            <span className="filename">{file.name}</span>
          ) : (
            <span>
              Drop a file here, or{" "}
              <button
                type="button"
                className="link"
                onClick={() => fileInputRef.current?.click()}
              >
                choose one
              </button>
              {mode === "decrypt" && " (a .thexweb file)"}
            </span>
          )}
        </label>

        <label className="field">
          <span>Password</span>
          <div className="password-row">
            <input
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete={mode === "encrypt" ? "new-password" : "current-password"}
              required
            />
            <button
              type="button"
              className="link"
              onClick={() => setShowPassword((v) => !v)}
            >
              {showPassword ? "Hide" : "Show"}
            </button>
          </div>
        </label>

        {mode === "encrypt" && (
          <label className="field">
            <span>Confirm password</span>
            <input
              type={showPassword ? "text" : "password"}
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              autoComplete="new-password"
              required
            />
          </label>
        )}

        <button type="submit" className="primary" disabled={!canSubmit}>
          {busy ? "Working..." : mode === "encrypt" ? "Encrypt" : "Decrypt"}
        </button>

        {error && (
          <p className="message error" role="alert">
            {error}
          </p>
        )}

        {result && downloadUrl && (
          <p className="message success">
            Done.{" "}
            <a href={downloadUrl} download={downloadName}>
              Download {downloadName}
            </a>
          </p>
        )}
      </form>

      <footer className="footer">
        <p>
          Own format (<code>.thexweb</code>), not compatible with the
          desktop/CLI <code>.thex</code> files - AES-256-GCM +
          PBKDF2-SHA256 (600,000 iterations), both native to this browser.
          See the project README for why, and what that trades away versus
          the desktop tool's Argon2id + XChaCha20-Poly1305.
        </p>
      </footer>
    </div>
  );
}
