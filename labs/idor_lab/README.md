# Local IDOR lab (authorized testing)

Minimal multi-user API for validating AccessProbe on a real HTTP target you control.

## Start

```bash
python labs/idor_lab/server.py 8765
```

## Sessions

Set cookie `session` to:

| Value | user_id | role |
|-------|---------|------|
| `alice` | 1 | user |
| `bob` | 2 | user |
| `admin` | 3 | admin |

Cookie files are ready under `cookies/`.

## Endpoints

- `GET /vuln/profile?user_id=N` — **broken** object-level auth
- `GET /secure/profile?user_id=N` — **correct** ACL (own or admin)
- `GET /orders?order_id=N` — **broken** order access
- `GET /` — HTML for `accessprobe discover`

## Example scans

```bash
accessprobe scan --config labs/idor_lab/scan_vuln.yaml --report /tmp/vuln.json
accessprobe scan --config labs/idor_lab/scan_secure.yaml --report /tmp/secure.json
accessprobe discover --url http://127.0.0.1:8765/ --cookie 'session=alice'
```

See [docs/TEST_RESULTS.md](../../docs/TEST_RESULTS.md) for full results and TP/FP analysis.
