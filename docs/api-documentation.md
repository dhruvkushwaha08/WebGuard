# API reference

Unless noted, JSON endpoints return an object with data or an `error` string. Protected endpoints require an authenticated session. State-changing routes require CSRF via `X-CSRF-Token` or form `csrf_token`, except login and registration.

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/health` | Public | Liveness JSON |
| POST | `/auth/register` | Public, throttled | Create regular account |
| POST | `/auth/login` | Public, throttled | Start session |
| POST | `/auth/logout` | Authenticated + CSRF | Clear session |
| GET | `/dashboard` | Authenticated | Dashboard UI |
| GET | `/analytics` | Authenticated | Analytics UI |
| GET | `/api/analytics/attacks?days=7` | Authenticated | KPI, type/severity distribution, trends, latest events |
| GET | `/events` | Authenticated | Event UI |
| GET | `/api/security/events` | Authenticated | Event filters and pagination |
| GET | `/api/security/events/<id>` | Authenticated | One event, 404 if absent |
| POST | `/api/security/simulate` | Authenticated + CSRF | Non-destructive local detector simulation |
| GET | `/api/admin/users` | Admin | User listing without password hashes |
| PUT | `/api/admin/users/<id>/status` | Admin + CSRF | Enable/disable another account |

Event list query parameters: `page` (default 1), `per_page` (1–100, default 20), `attack_type`, `severity`, `action`, `date_from`, `date_to`, `q` (up to 100 characters), `sort` (`timestamp`, `attack_type`, `severity`, `path`), and `direction` (`asc` or `desc`). SQL values are bound; sort/direction are allow-listed.

Example authenticated simulation request:

```json
{"category":"sqli","payload":"' OR '1'='1"}
```

Response includes `detected`, `findings`, `action`, and a message. The test endpoint does not execute a submitted payload against SQL or a browser.
