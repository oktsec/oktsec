# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Oktsec, please report it through
[GitHub Security Advisories](https://github.com/oktsec/oktsec/security/advisories/new).

**Do not open a public issue.**

## Scope

### In Scope

- Proxy authentication and authorization bypass
- Ed25519 signature verification flaws
- Policy engine bypass or ACL circumvention
- Audit log tampering or integrity issues
- Rule engine evasion
- Dashboard authentication bypass
- Quarantine queue escape
- Dependency vulnerabilities

### Out of Scope

- Findings detected in third-party agent content (that's what Oktsec is supposed to find)
- Third-party library vulnerabilities without a demonstrated exploit path
- Social engineering attacks

## Response Timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgment | 48 hours |
| Initial assessment | 7 days |
| Fix or mitigation | 30 days |

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Older releases | Best effort |

## Disclosure

We follow coordinated disclosure. We will:

1. Confirm the vulnerability
2. Develop a fix
3. Release a patch
4. Credit the reporter (unless anonymity is requested)
