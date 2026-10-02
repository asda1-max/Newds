# NEWDS

Personal notes vault built with Flask and SQLite.

## Run locally

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:NEWDS_SECRET = "replace-this-with-a-long-random-secret"
python app.py
```

Open http://127.0.0.1:5000. The first five accounts can register. SQLite and private uploaded files are created under Flask's `instance` directory by default.

## Upload constraints

- Each file must be strictly smaller than 1 GiB.
- Images must be strictly smaller than 10 MiB.
- The cap applies to each file, while the HTTP request has a 1 GiB + 64 MiB aggregate limit.
- Upload storage is private and is served only after checking the signed-in owner.

## Note encryption

Encrypted notes use Scrypt-derived keys and AES-GCM authenticated encryption. The note password is never stored. It cannot be reset; losing it means losing access to that note and its encrypted attachments. Use a unique, strong `NEWDS_SECRET` in any deployment.
