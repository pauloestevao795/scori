# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.7.x   | ✅ Yes    |
| < 0.7   | ❌ No     |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report security issues by email to **pestevao@e-safer.com.br** with the subject line
`[scori] Security Vulnerability`.

Include:
- A description of the vulnerability
- Steps to reproduce
- The version of scori affected
- Any potential impact assessment

You will receive an acknowledgement within 48 hours. If the issue is confirmed, a fix
will be released as soon as possible (target: within 14 days for critical issues).

## Security Considerations

scori reads local manifest files (`requirements.txt`, `pyproject.toml`, `setup.cfg`) and
makes outbound HTTP requests to public APIs:

| Endpoint | Data sent |
|----------|-----------|
| `https://pypi.org/pypi/{pkg}/json` | Package name only |
| `https://api.github.com/repos/{owner}/{repo}/releases` | Owner/repo from PyPI metadata |
| `https://api.osv.dev/v1/query` | Package name and version |

No telemetry, no user-identifying data, and no project source code is ever transmitted.
Local cache is stored at `~/.cache/scori/` and is readable only by the current user.

If you use `GITHUB_TOKEN`, scori passes it as a Bearer token in the `Authorization`
header to the GitHub API. Treat this token with the same care as any other credential.

## Dependency Security

scori's own dependencies are tracked with `pip-audit` in CI and audited against the
OSV database on every release. The current status is shown by the CI badge in the README.
