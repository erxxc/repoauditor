# Security policy

## Supported version

Security fixes are made on the current `main` branch. No released compatibility
branches are currently maintained.

## Reporting a vulnerability

Do not disclose suspected vulnerabilities in a public issue, discussion, or pull
request. Use GitHub's private vulnerability-reporting form for this repository:

https://github.com/erxxc/repoauditor/security/advisories/new

Private vulnerability reporting must be enabled before the repository is made
public. Include the affected revision, a minimal reproduction, likely impact, and
any suggested remediation. Do not include live credentials, proprietary source,
customer data, or data obtained without authorization.

The maintainer will acknowledge a report when it is reviewed, coordinate a
remediation and disclosure timeline appropriate to the issue, and credit the
reporter unless anonymity is requested.

## Scope and safe testing

RepoAuditor processes untrusted source and can invoke external scanners and model
providers. Test only repositories you are authorized to inspect. Do not use a
report to access third-party systems, execute acquired repository code, or submit
proprietary source to a hosted provider without permission.
