# Security Policy

THEncrypterX is a personal, single-maintainer project. There is no bug
bounty and no dedicated security team - reports are handled by the
maintainer directly.

## Supported versions

| Version | Supported |
|---|---|
| 1.x (`main`) | Yes |
| < 1.0 | No - pre-release, not tagged |

Only the latest tagged release and `main` receive fixes. There are no
long-term-support branches.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.** Public
issues are for bugs and feature requests; a vulnerability report there is
visible to anyone before a fix exists.

Instead, email **emondewan994@gmail.com** with:

- A description of the vulnerability and its impact (what an attacker
  could do, and against which threat-model assumption in
  [`docs/threat-model.md`](docs/threat-model.md) it breaks)
- Steps to reproduce, or a minimal `.thex` file / script that demonstrates it
- The version or commit hash you tested against
- Your assessment of severity, if you have one

You should get an acknowledgment within a few days. There is no formal SLA
for a fix, since this is a personal project maintained outside of paid work,
but confirmed vulnerabilities are prioritized over feature work.

## What counts as in scope

In scope: anything that breaks a guarantee stated in
[`docs/threat-model.md`](docs/threat-model.md) under "What is protected, and
how" - for example, a way to decrypt without the password, a way to make a
tampered file pass authentication, or a memory-safety bug in the `.thex`
parser reachable from an untrusted file.

Out of scope (already documented as not protected, not a vulnerability
report): the `.thex` file's size leaking, secure deletion not being
guaranteed on SSDs/CoW filesystems, lack of post-quantum primitives, or
attacks that assume the attacker already controls the machine while you are
actively using it. See "What is explicitly NOT protected" in the threat
model before reporting one of these.

## Responsible disclosure

Please give a reasonable amount of time for a fix and a release before any
public disclosure (blog post, talk, social media, public issue). If a
vulnerability is under active exploitation or already public, say so in your
report so it can be prioritized accordingly - but please still report
privately first rather than filing a public issue.

## Security limitations to know before relying on this project

This is a portfolio/learning project, not an audited product. It has not
had an independent third-party security audit. Read
[`docs/threat-model.md`](docs/threat-model.md) in full before using it for
anything where a mistake would be costly - it documents both what is
defended and what is explicitly not.
