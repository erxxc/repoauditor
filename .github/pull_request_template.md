## Summary

Describe the behavior changed and why.

## Security and evidence boundaries

- [ ] No credentials, proprietary source, raw provider output, or production data are included.
- [ ] New or changed findings preserve citation and provenance requirements.
- [ ] Acquired repository code is not executed.
- [ ] Prompt/template changes use a new versioned artifact and include evaluation evidence.
- [ ] Third-party material includes its source, pinned revision, and license.

## Validation

- [ ] `uv run pytest -m "not integration and not live"`
- [ ] Relevant focused tests
- [ ] External-scanner or live lanes are identified when intentionally deferred

## Operational impact

Note migrations, provider usage, new network hosts, deployment requirements, or state that none apply.
