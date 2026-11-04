# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems in GroundTrace itself.

Report privately through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability**. Include what you found, how to reproduce it, and the
impact you expect. You'll get an acknowledgement, and a fix or a decision, as soon as
is practical; reporters are credited unless they ask not to be.

In scope: the API and dashboard (authentication, injection, XSS, CSP bypass), secret
handling, the alert pipeline, and anything that could make the tool send data
somewhere it shouldn't.

Out of scope: vulnerabilities in the CVEs GroundTrace *reports on* — report those to
the affected vendor or via [CVE.org](https://www.cve.org/).

## How the tool is designed to stay safe

- **Localhost by default.** The API refuses to bind to a network interface unless
  `GROUNDTRACE_API_KEY` is set; the key is checked in constant time on every request
  except `/health`.
- **Secrets stay out of the repo.** Keys live in a git-ignored `.env`; `.env.example`
  holds names only. Tokens are never printed in logs or alert failures.
- **Collected data is treated as hostile.** Dark-web and web-search text is rendered as
  text only; links are restricted to `http(s)`; the dashboard runs under a strict
  Content-Security-Policy with no external assets.
- **Passive collection only.** The tool reads public feeds and APIs; it does not scan,
  probe or exploit anything, and it never downloads or executes exploit code.
- **Container hardening.** The Docker image runs as a non-root user with a health check
  and publishes its port on `127.0.0.1` only.
