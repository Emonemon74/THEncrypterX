# THEncrypterX — Improvement Roadmap

## 1. Goal

The goal of this roadmap is to evolve **THEncrypterX** from a strong encryption-focused project into a polished, production-oriented, security-conscious open-source application.

The focus should be on:

- Production readiness
- Security testing and documentation
- Better user experience
- Large-file reliability and performance
- Cross-platform distribution
- Portfolio and interview value

> **Important:** Cryptographic software should not be marketed as fully secure or production-ready without appropriate security review. Improvements in this document are engineering goals, not a security audit.

---

# 2. Current Strengths

THEncrypterX already has a strong technical foundation:

- XChaCha20-Poly1305
- AES-256-GCM
- Argon2id password-based key derivation
- HKDF-based key separation
- Streaming/chunked encryption
- Parallel processing
- Authenticated metadata
- Tamper detection
- Atomic file writes
- Versioned `.thex` container format
- CLI
- PySide6 desktop GUI
- Automated tests
- Property-based testing
- Cross-platform CI
- Threat-model and file-format documentation
- Benchmarking

The next stage should therefore focus less on adding more cryptographic algorithms and more on **engineering the complete product**.

---

# 3. Recommended Priority

## Priority 1 — Production Polish

1. Improve README
2. Add architecture diagrams
3. Add screenshots/GIFs
4. Improve installation instructions
5. Add practical CLI examples
6. Add configuration documentation
7. Add GitHub Releases

## Priority 2 — Security Engineering

1. Expand security documentation
2. Add fuzz testing
3. Expand parser/input validation tests
4. Add integrity verification
5. Document password/security limitations
6. Review error handling and secret exposure

## Priority 3 — Distribution

1. Build standalone executables
2. Automate release builds
3. Publish versioned releases
4. Add platform-specific installation instructions

## Priority 4 — Advanced File Handling

1. Resumable encryption/decryption
2. Better large-file support
3. Crash recovery
4. Improved progress reporting
5. Performance benchmarking

## Priority 5 — Portfolio Differentiator

Build an optional web interface with **client-side encryption/decryption**, so the server does not receive plaintext files or passwords.

---

# 4. Phase 1 — README and Documentation

## 4.1 Improve the README

The README should immediately answer:

- What is THEncrypterX?
- Why does it exist?
- What problem does it solve?
- Which cryptographic primitives are used?
- How does the file format work?
- How do I install it?
- How do I encrypt a file?
- How do I decrypt a file?
- What does the threat model cover?
- What are the limitations?

Recommended structure:

```text
THEncrypterX
├── Overview
├── Features
├── Security Model
├── Architecture
├── Installation
├── CLI Usage
├── Desktop Usage
├── File Format
├── Cryptography
├── Threat Model
├── Performance
├── Testing
├── Development
└── Roadmap
```

---

# 5. Phase 2 — Architecture Documentation

Create:

```text
docs/
├── architecture.md
├── cryptography.md
├── security.md
├── threat-model.md
├── file-format.md
├── performance.md
└── development.md
```

## Architecture Diagram

Document the flow:

```text
                    User
                     |
          +----------+----------+
          |                     |
         CLI                 Desktop GUI
          |                     |
          +----------+----------+
                     |
               Core Library
                     |
          +----------+----------+
          |                     |
     Key Management        File Processing
          |                     |
      Argon2id/HKDF        Chunked I/O
          |                     |
          +----------+----------+
                     |
              AEAD Encryption
                     |
             .thex Container
```

---

# 6. Phase 3 — Cryptography Documentation

Create `docs/cryptography.md`.

Explain the reason for every primitive.

## Argon2id

Document:

- Why passwords should not directly become encryption keys
- Salt generation
- Memory/time parameters
- Password-based key derivation
- Brute-force resistance

## HKDF

Document:

- Master key
- Data-encryption key
- Metadata key
- Domain separation

Example:

```text
Password
   |
 Argon2id
   |
Master Key
   |
  HKDF
   +------------------+
   |                  |
Data Key         Metadata Key
   |                  |
   |                  |
Chunks             Metadata
```

## XChaCha20-Poly1305

Explain:

- Confidentiality
- Authentication
- Nonce handling
- Why XChaCha20 is useful for large/streaming workloads

## AES-256-GCM

Document it as an alternative AEAD construction and explain when users might choose it.

---

# 7. Phase 4 — Integrity Verification

Add a command such as:

```bash
thencrypterx verify file.thex
```

Example output:

```text
THEncrypterX Verification
-------------------------
Container:        VALID
Format version:   1
Algorithm:        XChaCha20-Poly1305
Chunks:           1284
Metadata:         VALID
Authentication:   VALID
Integrity:        PASS
```

The command should verify the container without exposing plaintext.

## Tests

Test:

- Modified ciphertext
- Modified metadata
- Reordered chunks
- Deleted chunks
- Duplicated chunks
- Truncated container
- Invalid header
- Invalid version
- Invalid authentication tag

---

# 8. Phase 5 — Fuzz Testing

This should be a major security improvement.

Focus fuzzing on:

```text
.thex parser
     |
     +-- Header
     +-- Metadata
     +-- Chunk records
     +-- Length fields
     +-- Version fields
     +-- Authentication data
```

The parser should not:

- Crash
- Hang indefinitely
- Read outside valid boundaries
- Allocate unreasonable amounts of memory
- Accept malformed authenticated data

Possible tooling:

- Hypothesis
- Atheris
- libFuzzer-compatible tooling

Start with parser-focused fuzzing rather than fuzzing the cryptographic primitives themselves.

---

# 9. Phase 6 — Key File Support

Add optional key-file based encryption.

Example:

```bash
thencrypterx keygen --output mykey.thexkey
```

Then:

```bash
thencrypterx encrypt secret.pdf --key-file mykey.thexkey
```

And:

```bash
thencrypterx decrypt secret.pdf.thex --key-file mykey.thexkey
```

Architecture:

```text
                Key Source
               /                        /                     Password        Key File
            |                |
         Argon2id        Random Key
            |                |
            +-------+--------+
                    |
                   HKDF
                    |
              Encryption Keys
```

Document the risks of losing the key file.

---

# 10. Phase 7 — Resumable Encryption

This is an advanced feature and should come after the security foundation is stable.

Example:

```text
10 GB file

Chunk 1  ✓
Chunk 2  ✓
Chunk 3  ✓
Chunk 4  ✓
Chunk 5  ✗
```

Instead of restarting:

```text
Resume from Chunk 5
```

## Requirements

The design should account for:

- Crash recovery
- Partial containers
- Chunk authentication
- Container consistency
- Duplicate chunks
- Missing chunks
- Finalization state
- Atomic recovery

Do not implement this by simply appending data blindly. The container format should explicitly represent resumable state.

---

# 11. Phase 8 — Large File Support

Improve handling of very large files.

Goals:

- Constant or bounded memory usage
- Efficient chunk processing
- Predictable I/O
- Cancellation support
- Accurate progress reporting
- Safe recovery after interruptions

Example:

```text
Input File
    |
    v
+---------+
| Chunk 1 | ---> Encrypt ---> Write
+---------+
| Chunk 2 | ---> Encrypt ---> Write
+---------+
| Chunk 3 | ---> Encrypt ---> Write
+---------+
|   ...   |
+---------+
```

Memory should not scale linearly with file size.

---

# 12. Phase 9 — Better CLI

Suggested commands:

```bash
thencrypterx encrypt input.pdf
thencrypterx decrypt input.pdf.thex
thencrypterx verify input.pdf.thex
thencrypterx info input.pdf.thex
thencrypterx benchmark
thencrypterx keygen
```

## `info`

Example:

```bash
thencrypterx info secret.pdf.thex
```

Output:

```text
Container Information
---------------------
Format:       THEX
Version:      1
Algorithm:    XChaCha20-Poly1305
Chunk Size:   4 MiB
Chunks:       320
Metadata:     Encrypted
```

Do not expose secrets, keys, passwords, or sensitive plaintext metadata.

---

# 13. Phase 10 — Benchmarking

Expose benchmarking through the CLI:

```bash
thencrypterx benchmark
```

Measure:

- Encryption throughput
- Decryption throughput
- Different chunk sizes
- Worker counts
- Different algorithms
- Small files
- Large files
- CPU utilization
- Memory usage

Example:

```text
Benchmark
------------------------------
File size:        1 GB

XChaCha20-Poly1305
Workers: 1        XXX MB/s
Workers: 4        XXX MB/s
Workers: 8        XXX MB/s

AES-256-GCM
Workers: 1        XXX MB/s
Workers: 4        XXX MB/s
Workers: 8        XXX MB/s
```

Use actual measured results. Never hard-code or invent benchmark numbers.

---

# 14. Phase 11 — Desktop GUI Improvements

Improve the PySide6 interface with:

- Drag and drop
- Encryption/decryption tabs
- Password visibility toggle
- Password strength feedback
- Algorithm selection
- Chunk-size configuration
- Progress bar
- Current operation status
- Cancel button
- Error messages
- Verification status
- File information
- Recent operations

Suggested layout:

```text
+--------------------------------------+
|             THEncrypterX             |
+--------------------------------------+
|                                      |
|       Drag & Drop File Here          |
|                                      |
+--------------------------------------+
| Operation: Encrypt                   |
| Algorithm: XChaCha20-Poly1305       |
|                                      |
| Password: **************              |
|                                      |
| [ Start Encryption ]                 |
|                                      |
| Progress: ███████████░░░ 78%         |
|                                      |
+--------------------------------------+
```

---

# 15. Phase 12 — Standalone Executables

Package the desktop application so users don't need Python installed.

Target:

```text
Windows
macOS
Linux
```

Possible tools:

- PyInstaller
- Nuitka

The repository should provide downloadable builds through GitHub Releases.

---

# 16. Phase 13 — CI/CD Release Pipeline

Extend GitHub Actions.

Suggested pipeline:

```text
Pull Request
     |
     v
Lint
     |
Type Check
     |
Unit Tests
     |
Property Tests
     |
Security Tests
     |
Build
     |
Integration Tests
```

For releases:

```text
Git Tag
   |
   v
Build Windows
Build macOS
Build Linux
   |
   v
Run Tests
   |
   v
Publish GitHub Release
```

---

# 17. Phase 14 — Security Hardening

Review the application for:

## Secrets

Ensure:

- Passwords are never logged
- Keys are never logged
- API credentials are not committed
- Debug output does not expose sensitive values
- Exceptions don't expose secrets

## File handling

Review:

- Path traversal
- Symlinks
- Permissions
- Temporary files
- Atomic writes
- File replacement
- Partial output
- Disk-space failures

## Memory

Review:

- Password handling
- Key lifetime
- Large buffers
- Unbounded allocations
- Sensitive temporary data

Document platform limitations around secure memory wiping.

---

# 18. Phase 15 — Security Test Matrix

Create a security regression suite.

| Scenario | Expected Result |
|---|---|
| Wrong password | Decryption fails |
| Modified ciphertext | Authentication fails |
| Modified metadata | Authentication fails |
| Reordered chunks | Verification fails |
| Duplicated chunk | Verification fails |
| Deleted chunk | Verification fails |
| Truncated container | Verification fails |
| Invalid header | Parser rejects |
| Unsupported version | Parser rejects |
| Invalid chunk length | Parser rejects |
| Corrupted authentication tag | Authentication fails |
| Interrupted write | Original file remains intact |

Keep these tests automated.

---

# 19. Phase 16 — Web Interface (Optional Advanced Feature)

Only do this after the existing CLI/desktop application is polished.

A web application could provide:

```text
Browser
   |
   v
React / Vite
   |
   v
Client-side encryption
   |
   +-------> Encrypted .thex
   |
   v
Download
```

The key idea:

> Plaintext files and passwords should remain in the browser.

If a backend is added for file storage:

```text
Browser
   |
Encrypt locally
   |
   v
Encrypted file
   |
   v
Backend / Storage
```

The backend should only receive ciphertext if the architecture is intended to provide zero-knowledge-style storage.

This requires careful security design and should not be described as "zero knowledge" without clearly defining and validating the threat model.

---

# 20. Project Structure

A possible final structure:

```text
THEncrypterX/
├── src/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── property/
│   ├── security/
│   └── fuzz/
├── docs/
│   ├── architecture.md
│   ├── cryptography.md
│   ├── security.md
│   ├── threat-model.md
│   ├── file-format.md
│   ├── performance.md
│   └── development.md
├── benchmarks/
├── scripts/
├── .github/
│   └── workflows/
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
└── SECURITY.md
```

---

# 21. Add SECURITY.md

Create a dedicated security policy.

It should contain:

- Supported versions
- How to report vulnerabilities
- What information to include
- Expected response process
- Responsible disclosure guidance
- Security limitations

Do not encourage users to publicly disclose an unpatched vulnerability in an issue.

---

# 22. Add CHANGELOG.md

Use a consistent format:

```text
# Changelog

## [1.1.0]

### Added
- Integrity verification command
- Key-file support
- Improved CLI information output

### Changed
- Improved large-file processing

### Security
- Added parser fuzz testing
```

---

# 23. Add CONTRIBUTING.md

Document:

- Development setup
- Python version
- Dependency installation
- Running tests
- Running linting
- Running type checks
- Running benchmarks
- Pull request expectations

Example:

```bash
git clone <repository>
cd THEncrypterX

# Install dependencies
...

# Run tests
...

# Run linting
...

# Run benchmarks
...
```

---

# 24. Portfolio Presentation

The project should visually communicate the engineering work.

Add to README:

1. Project banner
2. Short description
3. Feature list
4. Architecture diagram
5. Security architecture
6. CLI screenshots
7. GUI screenshot
8. Example commands
9. Test status
10. CI status
11. Benchmark results
12. Threat model
13. Roadmap

Avoid making the README excessively long. Put deep technical explanations inside `docs/`.

---

# 25. Resume-Focused Improvements

For a resume, the highest-value improvements are:

### Must Have

- Strong README
- Architecture documentation
- Security documentation
- Automated tests
- CI/CD
- Standalone releases
- Fuzz testing
- Integrity verification

### Strong Advanced Additions

- Resumable encryption
- Large-file optimization
- Key-file support
- Benchmark CLI
- Crash recovery

### Optional Flagship Addition

- Client-side encrypted web application

---

# 26. Suggested Implementation Order

Follow this sequence instead of implementing everything simultaneously.

```text
STEP 1
README + documentation
        |
        v
STEP 2
Security review of current implementation
        |
        v
STEP 3
Integrity verification
        |
        v
STEP 4
Fuzz testing
        |
        v
STEP 5
CLI improvements
        |
        v
STEP 6
GUI improvements
        |
        v
STEP 7
Standalone builds
        |
        v
STEP 8
GitHub Releases + CI/CD
        |
        v
STEP 9
Key-file support
        |
        v
STEP 10
Large-file + resumable processing
        |
        v
STEP 11
Advanced benchmark system
        |
        v
STEP 12
Optional client-side web application
```

---

# 27. What NOT to Do

Avoid adding features simply to increase the feature count.

Do not add many unrelated algorithms such as:

```text
DES
3DES
Blowfish
Twofish
RSA
etc.
```

unless there is a concrete compatibility or architectural reason.

Also avoid claiming:

```text
"100% secure"
"unhackable"
"military-grade encryption"
"production-ready cryptography"
```

Instead, describe the concrete design and its tested properties.

---

# 28. Final Target

The final project should look like:

```text
                    THEncrypterX
                         |
       +-----------------+-----------------+
       |                 |                 |
      CLI            Desktop GUI       Optional Web
       |                 |                 |
       +-----------------+-----------------+
                         |
                    Core Library
                         |
        +----------------+----------------+
        |                |                |
    Key Mgmt         File Engine      Container
        |                |                |
    Argon2id           Streaming       .thex
    HKDF               Parallel        Format
        |                |                |
        +----------------+----------------+
                         |
                  AEAD Encryption
                         |
             XChaCha20 / AES-GCM
                         |
              Security + Integrity
                         |
              Tests / Fuzzing / CI
```

The goal is not simply to make THEncrypterX bigger.

The goal is to make it **better engineered, easier to use, easier to audit, easier to distribute, and easier to explain in an interview.**

---

# 29. Recommended "Definition of Done"

Before calling the next major version complete:

- [ ] README is polished
- [ ] Architecture is documented
- [ ] Cryptography choices are documented
- [ ] Threat model is documented
- [ ] Security policy exists
- [ ] Integrity verification exists
- [ ] Security regression tests exist
- [ ] Parser fuzzing exists
- [ ] CLI is polished
- [ ] GUI is polished
- [ ] Large-file behavior is tested
- [ ] Benchmark results are reproducible
- [ ] Cross-platform builds work
- [ ] GitHub Releases are automated
- [ ] No secrets are present in repository history
- [ ] Project limitations are clearly documented

---

## Recommended Final Scope

For your portfolio, I would stop after:

**Core encryption + security testing + polished CLI/GUI + releases + fuzzing + integrity verification + resumable large-file processing.**

The web application should be treated as an optional second stage rather than a requirement.

That gives THEncrypterX a clear identity as a **Python security/systems engineering project**, instead of turning it into an unfocused collection of features.


# 14A. GUI Worker Architecture and Management

Worker support should be treated as a **first-class GUI feature**, not only as an internal benchmark option.

The desktop GUI should remain responsive while encryption/decryption runs in the background.

## 14A.1 Target Architecture

```text
                    PySide6 GUI
                         |
              Signals / Commands
                         |
                         v
                Encryption Manager
                         |
                +--------+--------+
                |                 |
                v                 v
             Worker Pool     Progress Events
                |                 |
        +-------+-------+         |
        |       |       |         |
        v       v       v         v
     Worker  Worker  Worker    GUI Update
        |       |       |
        +-------+-------+
                |
                v
          Core Crypto Engine
                |
                v
           .thex Container
```

The GUI should **not contain the encryption implementation itself**.

Instead:

- GUI handles presentation and user interaction.
- Encryption Manager coordinates the operation.
- Workers execute background tasks.
- Core crypto/file-processing code remains independent of PySide6.
- Workers communicate progress/errors back to the GUI through Qt signals.

This keeps the core library reusable from the CLI and GUI.

---

## 14A.2 Worker Configuration

Add worker configuration to the GUI:

```text
Workers:
[ Auto ▼ ]

Options:
- Auto
- 1
- 2
- 4
- 8
- Custom
```

Also expose chunk size:

```text
Chunk Size:
[ 4 MiB ▼ ]
```

Possible options:

```text
1 MiB
4 MiB
8 MiB
16 MiB
32 MiB
Custom
```

The GUI should provide sensible defaults rather than forcing users to understand concurrency internals.

---

## 14A.3 Worker Status Panel

During an operation, show worker activity.

Example:

```text
┌─────────────────────────────────────────┐
│ Workers                                 │
├─────────────────────────────────────────┤
│ Worker 1   ████████████░░  82%          │
│ Worker 2   █████████████░  91%          │
│ Worker 3   ██████████░░░░  73%          │
│ Worker 4   ██████████████  Done         │
├─────────────────────────────────────────┤
│ Overall   ███████████░░░  84%            │
│ Speed:    425 MB/s                       │
│ ETA:      00:12                          │
└─────────────────────────────────────────┘
```

The GUI should distinguish between:

```text
Queued
Processing
Completed
Failed
Cancelled
```

---

## 14A.4 Progress Reporting

Progress should not be calculated by repeatedly polling the worker threads from the GUI.

Prefer an event-driven design:

```text
Worker
   |
   | progress(chunk_id, bytes_processed)
   v
Encryption Manager
   |
   | aggregate progress
   v
Qt Signal
   |
   v
GUI
```

The manager can aggregate:

- Total bytes processed
- Completed chunks
- Active workers
- Failed workers
- Current throughput
- Estimated remaining time

Example signal concepts:

```text
progress_changed(percent)
throughput_changed(bytes_per_second)
worker_status_changed(worker_id, status)
operation_finished(result)
operation_failed(error)
```

Use Qt's signal/slot mechanism so UI updates occur safely on the GUI thread.

---

## 14A.5 Keeping the GUI Responsive

Do not execute encryption directly inside a button callback such as:

```python
def on_encrypt_clicked():
    encrypt_file(...)
```

if `encrypt_file()` performs the entire operation synchronously.

Instead:

```text
User clicks Encrypt
        |
        v
GUI creates operation
        |
        v
Encryption Manager
        |
        v
Worker Pool
        |
        +---- Worker 1
        +---- Worker 2
        +---- Worker 3
        +---- Worker 4
```

The GUI event loop remains available for:

- Progress updates
- Cancel
- Window movement
- UI interaction
- Error messages

---

## 14A.6 Cancellation

The GUI should provide:

```text
[ Cancel Encryption ]
```

Cancellation must be cooperative.

Recommended flow:

```text
User clicks Cancel
        |
        v
Cancellation requested
        |
        v
Manager sets cancellation state
        |
        v
Workers finish safe current operation
        |
        v
Workers stop accepting new chunks
        |
        v
Manager cleans up
        |
        v
Partial output handled safely
```

Do not simply terminate a worker in the middle of an unsafe file operation.

The final behavior should be clearly documented:

- Whether a partial `.thex` file is deleted
- Whether it is retained as a resumable file
- Whether the original input is untouched

---

## 14A.7 Error Handling

Worker failures should be propagated to the manager.

```text
Worker 3
   |
   | exception/error
   v
Encryption Manager
   |
   +--> stop/cancel remaining work
   |
   +--> safely finalize or discard partial output
   |
   v
GUI
   |
   v
User-friendly error message
```

The GUI should not display raw stack traces by default.

For example:

```text
Encryption failed

The operation could not be completed because
the output file could not be written.

No changes were made to the original file.
```

Detailed diagnostic information can be available through an expandable technical-details section or debug log.

Never expose:

- Passwords
- Encryption keys
- Sensitive plaintext
- Secret metadata

in logs or error messages.

---

## 14A.8 Worker Pool Design

Use a bounded worker pool rather than creating an unlimited number of threads.

Conceptually:

```text
                    Encryption Manager
                           |
                     Bounded Queue
                           |
          +----------------+----------------+
          |                |                |
          v                v                v
       Worker 1         Worker 2         Worker N
          |                |                |
          +----------------+----------------+
                           |
                       Output Stage
```

Important considerations:

- Limit worker count
- Avoid unbounded queues
- Avoid excessive memory usage
- Avoid multiple workers writing to the same file region unsafely
- Preserve deterministic chunk ordering where required by the container format
- Ensure authentication data is associated with the correct chunk index

---

## 14A.9 Ordered Output

Parallel processing introduces an important design problem.

Workers may finish out of order:

```text
Worker 1 → Chunk 1 → 100 ms
Worker 2 → Chunk 2 → 250 ms
Worker 3 → Chunk 3 → 120 ms
Worker 4 → Chunk 4 → 80 ms
```

Completion order:

```text
Chunk 4
Chunk 1
Chunk 3
Chunk 2
```

But the `.thex` container may require deterministic chunk ordering.

Therefore, use an output coordination stage:

```text
Workers
   |
   | completed chunks
   v
Result Buffer
   |
   | wait for expected chunk
   v
Ordered Writer
   |
   v
.thex Container
```

The implementation should avoid holding an unbounded number of completed chunks in memory.

---

## 14A.10 Threading vs Multiprocessing

Benchmark both approaches for the actual workload.

Possible options:

```text
QThread / QThreadPool
ThreadPoolExecutor
ProcessPoolExecutor
```

The choice should be based on:

- CPU behavior
- I/O behavior
- Cryptographic library implementation
- GIL behavior
- Serialization overhead
- Memory usage
- Cross-platform behavior

Do not assume that more workers always means higher throughput.

The GUI should therefore expose a reasonable default such as:

```text
Workers: Auto
```

and allow advanced users to override it.

---

## 14A.11 Worker Metrics

Show useful metrics without overwhelming normal users.

Basic mode:

```text
Progress: 78%
Speed: 425 MB/s
ETA: 00:12
```

Advanced mode:

```text
Workers: 4
Active: 4
Queued chunks: 8
Completed chunks: 312
Throughput: 425 MB/s
CPU usage: ...
Memory usage: ...
```

Do not expose metrics that are unreliable or misleading.

---

## 14A.12 GUI State Machine

The operation UI should have explicit states:

```text
IDLE
 |
 v
STARTING
 |
 v
RUNNING
 |
 +----------+
 |          |
 v          v
CANCELLING ERROR
 |          |
 v          v
CANCELLED FAILED
 |
 +------+
        |
        v
     COMPLETE
```

This prevents invalid interactions such as:

- Starting two encryption operations accidentally
- Clicking Encrypt repeatedly
- Closing the application while workers are still writing
- Starting decryption while a previous operation is active

---

## 14A.13 Window Close Handling

If encryption is running and the user closes the window:

```text
Close requested
      |
      v
Is operation running?
      |
   +--+--+
   |     |
  No    Yes
   |     |
 close   v
      Confirmation
          |
      +---+---+
      |       |
    Cancel   Keep Open
      |
      v
Graceful shutdown
```

Example:

```text
Encryption is still running.

Closing the application will stop the current operation.

[ Cancel Operation ]  [ Keep Running ]
```

The exact behavior should be chosen based on whether background operation support is implemented.

---

## 14A.14 Testing the Worker System

Add dedicated tests for concurrency.

### Unit Tests

- Worker initialization
- Worker configuration
- Chunk assignment
- Progress calculation
- Cancellation state
- Error propagation

### Integration Tests

- Single worker encryption
- Multi-worker encryption
- Multi-worker decryption
- Large files
- Different chunk sizes
- Different worker counts
- Cancellation
- Worker failure
- GUI shutdown during operation

### Correctness Tests

The following should produce equivalent plaintext after decryption:

```text
1 worker
2 workers
4 workers
8 workers
```

Test:

```text
Input
  |
  +--> 1 worker --> encrypted A
  |
  +--> 4 workers -> encrypted B
  |
  +--> 8 workers -> encrypted C
```

Then decrypt each output and verify:

```text
plaintext A == original
plaintext B == original
plaintext C == original
```

Do not require ciphertext from separate encryption runs to be identical if fresh random nonces/salts are intentionally used.

---

## 14A.15 Performance Tests

Benchmark:

```text
Workers: 1
Workers: 2
Workers: 4
Workers: 8
Workers: Auto
```

Across:

```text
100 MB
1 GB
5 GB
10 GB+
```

Record:

- Throughput
- Total execution time
- Peak memory
- CPU utilization
- Scaling efficiency

Example:

```text
Workers   Throughput   Memory   Time
1         measured     measured measured
2         measured     measured measured
4         measured     measured measured
8         measured     measured measured
```

Use actual measurements from the target environment.

---

## 14A.16 GUI Worker Roadmap

Implement in this order:

```text
1. Background encryption task
        |
        v
2. Progress signal
        |
        v
3. Worker pool
        |
        v
4. Worker count configuration
        |
        v
5. Cancellation
        |
        v
6. Error propagation
        |
        v
7. Ordered output coordination
        |
        v
8. Worker status panel
        |
        v
9. Throughput + ETA
        |
        v
10. Concurrency tests
        |
        v
11. Performance benchmarks
        |
        v
12. GUI polish
```

---

## 14A.17 Definition of Done

The GUI worker implementation is complete when:

- [ ] Encryption does not block the GUI thread
- [ ] Decryption does not block the GUI thread
- [ ] Worker count can be configured
- [ ] Auto worker mode exists
- [ ] Chunk size can be configured safely
- [ ] Progress is reported through signals/events
- [ ] Overall progress is accurate
- [ ] Worker status can be displayed
- [ ] Throughput is displayed
- [ ] ETA is reasonably calculated
- [ ] Cancellation is supported
- [ ] Worker failures are handled safely
- [ ] Partial output is handled safely
- [ ] Output ordering is correct
- [ ] Memory usage remains bounded
- [ ] Multiple worker counts produce correct plaintext
- [ ] GUI remains responsive under load
- [ ] Closing the application during an operation is handled safely
- [ ] Concurrency tests are automated
- [ ] Performance benchmarks are reproducible

---

# 14B. Recommended GUI Architecture After This Improvement

The target architecture becomes:

```text
                         THEncrypterX
                              |
                 +------------+------------+
                 |                         |
              CLI App                  PySide6 GUI
                 |                         |
                 +------------+------------+
                              |
                         Core Library
                              |
                    Encryption Manager
                              |
                    +---------+---------+
                    |                   |
                Worker Pool        Progress Events
                    |                   |
          +---------+---------+         |
          |         |         |         |
       Worker    Worker    Worker       |
          |         |         |          |
          +---------+---------+          |
                    |                    |
                    v                    |
              Crypto Engine             |
                    |                    |
              Chunk Processor            |
                    |                    |
                    v                    |
              Ordered Writer <-----------+
                    |
                    v
               .thex Container
```

This gives the project a clean separation between:

- UI
- orchestration
- concurrency
- cryptographic operations
- file I/O
- container formatting

That separation should be preserved as THEncrypterX grows.
