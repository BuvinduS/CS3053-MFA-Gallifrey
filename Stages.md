## Stage 1

- A FastAPI app with Jinja templates, SQLite through SQLAlchemy, and separate routes, services, models and templates.
- User with argon2-hashed passwords. Login uses the same error for an unknown user and a wrong password, and does a dummy hash check so both take about the same time.
- WebSession is an opaque server-side session. The cookie holds a random token and the database stores only its SHA-256 hash. The cookie is HttpOnly and SameSite=Lax, and Secure is on by default with an env override for local dev.
- `/login`, `/dashboard`, `/logout`, and an accessible form with labels, an role="alert" error, a skip link and a focus outline.
- Scaffolding on purpose: password alone creates a session. Stage 2 removes that.