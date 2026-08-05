# OWASP Juice Shop lab notes (authorized local testing)

This folder helps reproduce AccessProbe validation against a **local** Juice Shop instance.

## Prerequisites

1. Juice Shop installed and running on your machine (default `http://127.0.0.1:3000`).
2. AccessProbe installed: `pip install -e ".[dev]"` from the repo root.

```bash
# example
cd /path/to/juice-shop
npm start
```

## Automated setup + scan

```bash
# from accessprobe repo root
python labs/juice_shop/setup_and_scan.py
```

The script will:

1. Register two disposable users  
2. Log them in and capture JWT + basket IDs  
3. Confirm basket IDOR with HTTP ground truth  
4. Write a local `scan_basket.yaml` (gitignored — contains secrets)  
5. Run AccessProbe path-parameter scans  
6. Save reports under `labs/results/juice_shop/`

## Manual config template

Copy `scan_basket.example.yaml` and replace placeholders after you login via the API or browser.

```yaml
# URL MUST include the path placeholder {id}
url: "http://127.0.0.1:3000/rest/basket/{id}"
parameters:
  - name: id
    location: path
    value: "8"   # your low-priv basket id
```

Session auth uses headers:

```yaml
headers:
  Authorization: "Bearer <jwt>"
```

## Expected ground truth

| Call | Expected |
|------|----------|
| User A → own basket | 200 |
| User A → User B basket | **200** (classic Juice Shop basket IDOR) |

AccessProbe should report a **horizontal** finding with high confidence when the foreign basket returns 200 with a similar JSON body.

## Security note

- Do **not** commit files containing live JWTs.  
- `scan_basket.yaml`, `scan_users.yaml`, and `cookies/*.token` are gitignored.  
- Only scan Juice Shop instances you control.
