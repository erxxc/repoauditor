# OWASP RailsGoat benchmark anchor

- Kind: `benchmark` (deliberately vulnerable; not independent evaluation evidence)
- Materialization: pinned acquisition only; source is not redistributed in this repository.
- Upstream: https://github.com/OWASP/railsgoat.git
- Commit: `0222f7da3406ba3ab637bc6d24ae9366b5f0a680`
- License: MIT; upstream `LICENSE.md` is retained when materialized.
- Ground truth: human review of the deliberately vulnerable password-reset controller. It was
  not generated from repoauditor output.

This public snapshot may be analyzed with a hosted model. Proprietary code must never be added
to this corpus or sent to hosted models without explicit authorization.

Materialize with `python tests/fixtures/materialize_public_corpus.py <clone-cache> --fetch`.
