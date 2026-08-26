-- =============================================================================
-- HawkShield — PostgreSQL bootstrap
-- =============================================================================
-- Creates the `hawkshield` role and database and grants what the app needs.
-- Idempotent: safe to re-run. Re-running never changes an existing role's
-- password and never touches existing data.
--
-- Run as the postgres superuser, from the repo root:
--
--     sudo -u postgres psql -v ON_ERROR_STOP=1 -v hs_password=yourpassword \
--          -f deploy/postgres_setup.sql
--
-- Pass the password RAW (no quotes) — this script quotes it correctly via
-- format(%L). deploy/install_pi.sh reads it out of the DATABASE_URL you put in
-- .env and passes it here, so the two can never drift apart.
--
-- If -v hs_password is omitted the role is created with the password
-- 'hawkshield'. Acceptable only for an isolated lab Pi with localhost-only
-- auth. To change it later:
--
--     sudo -u postgres psql -c "ALTER ROLE hawkshield WITH PASSWORD 'new';"
--
-- ...and update DATABASE_URL in .env to match.
-- =============================================================================

\set ON_ERROR_STOP on

-- Default the password only if the caller did not supply one.
\if :{?hs_password}
\else
    \set hs_password hawkshield
    \echo '  note: -v hs_password not supplied; using the default placeholder.'
\endif

-- --- Role --------------------------------------------------------------------
-- CREATE ROLE has no IF NOT EXISTS. Generate the statement only when the role is
-- missing and let \gexec run it. (A DO block would not work here: psql does not
-- interpolate :variables inside dollar-quoted bodies.)
SELECT format('CREATE ROLE hawkshield LOGIN PASSWORD %L', :'hs_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hawkshield')
\gexec

-- --- Database ----------------------------------------------------------------
-- CREATE DATABASE cannot run inside a transaction block, hence \gexec again.
SELECT 'CREATE DATABASE hawkshield OWNER hawkshield ENCODING ''UTF8'''
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'hawkshield')
\gexec

-- --- Privileges --------------------------------------------------------------
GRANT ALL PRIVILEGES ON DATABASE hawkshield TO hawkshield;

-- Everything below applies inside the hawkshield database itself.
\connect hawkshield

-- PostgreSQL 15+ revokes CREATE on schema public from PUBLIC, so hand the schema
-- to the hawkshield role explicitly. Tables themselves are created afterwards by
-- `python -m backend.scripts.init_db`.
ALTER SCHEMA public OWNER TO hawkshield;
GRANT ALL ON SCHEMA public TO hawkshield;

-- Covers a re-install where tables already exist but are owned by someone else.
GRANT ALL PRIVILEGES ON ALL TABLES    IN SCHEMA public TO hawkshield;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO hawkshield;

ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES    TO hawkshield;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO hawkshield;

\echo 'postgres_setup.sql: done — role, database and privileges are ready.'
