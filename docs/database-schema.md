# Database schema

| Table | Purpose | Important fields |
|---|---|---|
| `users` | Accounts and role state | `username` and `email` unique; hashed password; `admin`/`user`; active flag |
| `security_events` | Append-oriented incident records | timestamp, attack type, severity, method, path, reason, action, status, source IP |
| `request_counts` | Daily aggregate request totals | date primary key, safe count, blocked count |
| `rate_limits` | Short-window login/register attempts | source IP and creation time |

The schema is created by the app factory. SQLite connections enable foreign-key enforcement. Application reads/writes use parameterized statements. The normal routes expose event listing/detail only; there is no event update or delete endpoint.

Security events intentionally do not store request bodies, usernames submitted to sign-in, passwords, cookies, authorization headers, or session identifiers.
