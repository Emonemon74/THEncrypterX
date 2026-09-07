# THEncrypterX

Secure file encryption system with authenticated encryption, a password-derived
key (Argon2id), and a versioned binary container format (`.thex`).

> **Status:** in development. See `THEncrypterX_Build_Guide.md` for the spec and
> build order.

## Features (implemented so far)

- _nothing yet — building the cryptographic core_

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest
```

## License

MIT
