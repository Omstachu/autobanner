# Potential Upgrades

Open ideas that aren't worth doing now but should be reconsidered later.

## Read-only Postgres user for the MCP

The Postgres MCP currently connects with whatever user is in `DATABASE_URL` — today that's `webhook`, which has full write access to the `compliance` database. The MCP runs in `--access-mode=restricted` so only `SELECT` is allowed at the protocol layer, but for defense-in-depth a dedicated read-only DB user is the right shape.

Setup sketch:

```sql
CREATE USER compliance_ro WITH PASSWORD '...';
GRANT CONNECT ON DATABASE compliance TO compliance_ro;
GRANT USAGE ON SCHEMA public TO compliance_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO compliance_ro;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO compliance_ro;
```

Then point the MCP at a separate `DATABASE_URL_RO` env var so the webhook server keeps using `webhook` while the MCP uses `compliance_ro`.
