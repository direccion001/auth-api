# Repository Guidelines

## Project Structure & Module Organization

This repository currently contains one Node.js service in `auth-api/`.

- `auth-api/src/index.js` starts the Express API, registers routes, and defines global error handling.
- `auth-api/src/routes/` contains HTTP route modules. Viewer routes live directly under `routes/`; mutable endpoints live under `routes/crud/`.
- `auth-api/src/middleware/` contains request guards such as JWT authentication and internal-user checks.
- `auth-api/src/db/pool.js` configures the shared MySQL connection pool.
- `auth-api/src/mail/` contains email delivery code and HTML templates.
- `auth-api/src/config/` stores shared configuration such as permission maps.

Keep new code close to its feature area. For example, add a new CRUD resource as `src/routes/crud/<resource>.js` and register it in `src/routes/crud/index.js`.

## Build, Test, and Development Commands

Run commands from `auth-api/`.

- `npm install` installs runtime and development dependencies.
- `npm run dev` starts the API with `nodemon` for local development.
- `npm start` starts the API with `node src/index.js`.
- `docker build -t auth-api .` builds the production container using Node 20 slim.
- `docker run -p 8080:8080 --env-file .env auth-api` runs the container locally.

The service listens on `PORT` or `8080` by default.

## Coding Style & Naming Conventions

Use CommonJS (`require`, `module.exports`) and two-space indentation. Prefer `const`, small helper functions for repeated validation or response logic, and Spanish domain naming where the database/API concept is already Spanish (`prospectos`, `seguimientos`, `planteles`). Route files should use kebab-case names; functions and local variables should use camelCase.

JSON responses should consistently include `ok`, `code`, and `message` for errors.

## Testing Guidelines

No test framework or `npm test` script is currently configured. When adding tests, introduce a clear test script in `package.json` and place tests beside the module or under `tests/`. Name tests after the behavior, for example `auth.login.test.js` or `seguimientos.create.test.js`. Prioritize authentication, permission checks, query parameters, and error responses.

## Commit & Pull Request Guidelines

Git history was not available in this environment, so use concise imperative commit messages such as `Add seguimiento CRUD route` or `Fix JWT expiration handling`. Pull requests should include a short summary, affected routes/modules, required environment changes, testing notes, and screenshots or sample API responses when behavior changes.

## Security & Configuration Tips

Keep secrets out of the repository. Required configuration includes values such as `JWT_SECRET`, `SQL_USER`, `SQL_PASSWORD`, `DB_NAME`, `INSTANCE_CONNECTION`, and optional `SQL_TIMEZONE`. Validate all request inputs before using them in queries, and keep parameterized SQL placeholders for database access.

## Database Access & Safety Rules

Permanent project databases:

- `ipr_db`
- `ipr_franq`

Use the local access script at `C:\Tools\ipr-db.ps1`. It starts Cloud SQL Proxy automatically when needed.

Examples:

- `& "C:\Tools\ipr-db.ps1" -Database ipr_db -Query "QUERY SQL"`
- `& "C:\Tools\ipr-db.ps1" -Database ipr_franq -Query "QUERY SQL"`

Before modifying any table, run `SHOW CREATE TABLE` for the affected table and review relevant dependencies. Before modifying any view, run `SHOW CREATE VIEW` for the affected view.

Allowed database operations: `SELECT`, `DESCRIBE`, `SHOW`, `SHOW CREATE TABLE`, `SHOW CREATE VIEW`, non-destructive `ALTER TABLE`, `ADD COLUMN`, `MODIFY COLUMN`, `CREATE VIEW`, and `CREATE OR REPLACE VIEW`.

Do not run the following without explicit user authorization: `DROP TABLE`, `DROP COLUMN`, `TRUNCATE`, `DELETE`, production-data `UPDATE`, or any destructive or irreversible change. If an operation may cause data loss, stop and ask for authorization before executing it.
