# DB-API cursor.execute

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-ce9054d3f415ddb1
api: DB-API cursor.execute
api_family: db.cursor.execute
runtime:
  language: python
  ecosystem: python-runtime
  package: db
  version: legacy-source-bound
capability_class: sql-exec
normative_authority: capability-facts-only
bound_sinks:
- sqlalchemy.session.execute
- sqlalchemy.connection.execute
- langchain.SQLDatabaseChain.run
roles:
- role_id: content
  description: Legacy controlled role content.
  bindings:
  - expression: text
    caller_bindable: true
- role_id: statement
  description: Legacy controlled role statement.
  bindings:
  - expression: statement
    caller_bindable: true
facets:
- facet_id: legacy-facet-d3b7e318
  capability: Execute ANY valid SQL statement that the underlying database engine accepts,
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-388cae43
  capability: Accept multi-statement strings separated by `;` on drivers/databases that
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-5826ed84
  capability: Arbitrary data exfiltration from EVERY table reachable by the connection's
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-7882cd05
  capability: 'Read arbitrary server-side files through database-specific functions:'
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-2ff5a0cd
  capability: 'Write arbitrary files to the server filesystem: `SELECT ... INTO'
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-51b1129f
  capability: Execute arbitrary OS commands on the database host through database-specific
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-c6ad069b
  capability: Escalate the database connection to OS-level code execution by writing a
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-da4e00b3
  capability: 'Perform Second-Order SQL Injection through database-resident mechanisms:'
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-724598c7
  capability: 'Create, alter, or drop database users and roles: `CREATE USER`,'
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-9364e154
  capability: 'Enable/disalbe database features that widen attack surface:'
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-676cbd9c
  capability: 'Access cross-database and cross-schema data: `SELECT * FROM'
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-941be667
  capability: Perform blind data extraction through boolean-based or time-based side
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-0555db65
  capability: Use UNION-based injection to combine attacker-controlled results with benign
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-8acabb74
  capability: 'Stack queries to run independent statements in a single call:'
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-605bdd5c
  capability: 'Modify the database schema destructively: `DROP TABLE/DATABASE/INDEX`,'
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-83e0807b
  capability: 'Leverage SQLite-specific attack surface when the backend is sqlite3:'
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-98cf113e
  capability: 'Exploit PostgreSQL-specific extension points when the backend is PostgreSQL:'
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-1ba4139d
  capability: 'Exploit MySQL/MariaDB-specific extension points: `LOAD DATA INFILE` for'
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-5c110b30
  capability: Exploit SQL Server-specific extension points (when using pyodbc/pymssql
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-912be1a3
  capability: Exploit Oracle-specific extension points (when using cx_Oracle/oracledb
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-a12b8042
  capability: Exfiltrate data through out-of-band (OOB) channels, bypassing firewalls and
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-7927d00f
  capability: 'Perform denial-of-service against the database: `SELECT ... FROM ... WHERE'
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-5f1b4919
  capability: Exploit database-specific type confusion, overflow, or parser bugs through
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-af4d77fc
  capability: 'Exploit implicit client-side behaviors: the DB-API `execute()` call may'
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-e98cca04
  capability: 'Execute parameterized statements with attacker-controlled SQL structure:'
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-5434184e
  capability: 'Chain DB-API methods for amplification: after `execute()`, call'
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-476416ec
  capability: 'Silence errors to stay stealthy: wrap payloads in exception-handling SQL'
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
- facet_id: legacy-facet-39d99aa2
  capability: 'Enumerate database metadata to map the attack surface:'
  role_ids:
  - content
  - statement
  activation:
    any_of:
    - predicate: role-bound
      subject: content
      operator: equals
      value: true
    - predicate: role-bound
      subject: statement
      operator: equals
      value: true
library_guarantees: []
defaults:
- default_id: legacy-default-8688e283
  role_id: null
  value: DB-API 2.0 (PEP 249) specifies that `execute()` runs the SQL statement
  security_effect: DB-API 2.0 (PEP 249) specifies that `execute()` runs the SQL statement
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-05671b0e
  role_id: null
  value: By default, DB-API connections DO NOT limit statement types. A single
  security_effect: By default, DB-API connections DO NOT limit statement types. A single
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-461123fc
  role_id: null
  value: 'Multi-statement execution is driver-dependent but widely supported:'
  security_effect: 'Multi-statement execution is driver-dependent but widely supported:'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-414e5c26
  role_id: null
  value: Autocommit is OFF by default in PEP 249; the first DML implicitly starts a
  security_effect: Autocommit is OFF by default in PEP 249; the first DML implicitly starts a
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-a16cbd59
  role_id: null
  value: The cursor inherits the connection's database, schema, role, and session
  security_effect: The cursor inherits the connection's database, schema, role, and session
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-de231082
  role_id: null
  value: SQLite's `ATTACH DATABASE` can open ANY file the process has read access to
  security_effect: SQLite's `ATTACH DATABASE` can open ANY file the process has read access to
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-6bab5da8
  role_id: null
  value: Database user permissions are enforced by the database engine, not by
  security_effect: Database user permissions are enforced by the database engine, not by
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-608b01a2
  role_id: null
  value: Many drivers implicitly reconnect on connection loss (MySQL Connector/Python
  security_effect: Many drivers implicitly reconnect on connection loss (MySQL Connector/Python
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-e3c19708
  role_id: null
  value: sqlite3 connections in Python are file-based; `execute()` operates on the
  security_effect: sqlite3 connections in Python are file-based; `execute()` operates on the
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: 'import sqlite3


    conn = sqlite3.connect(":memory:")

    cursor = conn.cursor()

    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")

    cursor.execute("INSERT INTO users (name) VALUES (?)", ("Alice",))

    cursor.execute("SELECT * FROM users WHERE name = ?", ("Alice",))

    rows = cursor.fetchall()

    assert rows == [(1, "Alice")]

    '
  capability_edge: "import sqlite3\n\nconn = sqlite3.connect(\":memory:\")\ncursor = conn.cursor()\n\n# 1) CREATE TABLE as attacker wishes (DDL)\ncursor.execute(\"CREATE TABLE persistent_backdoor (cmd TEXT)\")\n\n# 2) INSERT malicious data (DML, persists beyond this transaction)\ncursor.execute(\n    \"INSERT INTO persistent_backdoor VALUES ('<?php system($_GET[\\\"c\\\"]);?>')\"\n)\n\n# 3) ATTACH an arbitrary file as a database (SQLite filesystem read pivot)\n#    — reads /etc/hostname into a table the attacker controls\ncursor.execute(\"CREATE TABLE hostname (content TEXT)\")\ncursor.execute(\"ATTACH DATABASE '/etc/hostname' AS hostfile\")\n# In practice on a real SQLite DB with write access to disk:\ncursor.execute(\"ATTACH DATABASE '/tmp/evil.db' AS evil\")\n\n# 4) Write to filesystem via ATTACH + CREATE TABLE (SQLite file-write pivot)\ncursor.execute(\"ATTACH DATABASE '/tmp/attacker_payload.db' AS pwnd\")\ncursor.execute(\"CREATE TABLE pwnd.evil (data TEXT)\")\ncursor.execute(\"INSERT\
    \ INTO pwnd.evil VALUES ('malicious content')\")\n\n# 5) Blind time-based data extraction (SQLite: no SLEEP, but recursive CTE DoS)\ncursor.execute(\n    \"WITH RECURSIVE r(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM r) \"\n    \"SELECT * FROM r LIMIT 99999999\"\n)\n\n# 6) Enumerate schema — discover all tables\ncursor.execute(\"SELECT name, sql FROM sqlite_master WHERE type='table'\")\nschema = cursor.fetchall()\n\n# 7) Drop all user tables destructively\nfor (name,) in cursor.execute(\n    \"SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'\"\n).fetchall():\n    cursor.execute(f\"DROP TABLE IF EXISTS {name}\")\n\n# 8) PRAGMA abuse — disable protections, expose internals\ncursor.execute(\"PRAGMA writable_schema=ON\")\ncursor.execute(\"DELETE FROM sqlite_master WHERE type='table'\")\n\n# 9) Second-order persistence via trigger: every future INSERT runs attacker SQL\ncursor.execute(\"CREATE TABLE log (entry TEXT)\")\ncursor.execute(\n    \"CREATE TRIGGER backdoor\
    \ AFTER INSERT ON log \"\n    \"BEGIN \"\n    \"  INSERT INTO persistent_backdoor VALUES ('trigger fired on: ' || NEW.entry); \"\n    \"END\"\n)\ncursor.execute(\"INSERT INTO log VALUES ('benign input')\")\n\n# 10) Stack multiple statements in a single execute() call\ncursor.execute(\n    \"CREATE TABLE exfil (data TEXT); \"\n    \"INSERT INTO exfil VALUES ('secret1'); \"\n    \"INSERT INTO exfil VALUES ('secret2'); \"\n    \"SELECT * FROM exfil\"\n)\nprint(cursor.fetchall())  # [('secret1',), ('secret2',)]\n\n# 11) load_extension() — native code execution (requires sqlite3 with\n#     extension loading enabled at compile time)\n# cursor.execute(\"SELECT load_extension('/path/to/evil.so')\")\n"
provenance:
- https://peps.python.org/pep-0249/ — Python DB-API 2.0 specification (PEP 249)
- '{''CWE-89'': "Improper Neutralization of Special Elements used in an SQL Command (''SQL Injection'')"}'
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- https://portswigger.net/web-security/sql-injection — SQL injection techniques and cheat sheet
- https://www.sqlite.org/c3ref/exec.html — SQLite C API (underlies Python sqlite3)
- https://www.postgresql.org/docs/current/sql-copy.html — PostgreSQL COPY (includes PROGRAM variant)
- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql — SQL Server xp_cmdshell
- https://dev.mysql.com/doc/refman/8.4/en/load-data.html — MySQL LOAD DATA INFILE (includes LOCAL variant for SSRF)
```
