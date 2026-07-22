# OWASP Juice Shop benchmark anchor

- Kind: `benchmark` (deliberately vulnerable; not independent evaluation evidence)
- Materialization: pinned acquisition only; source is not redistributed in this repository.
- Upstream: https://github.com/juice-shop/juice-shop.git
- Commit: `33518f5a0911e25d9df747b1e70fb7af279a755c`
- License: MIT; upstream `LICENSE` is retained when materialized.
- Ground truth: human review of the intentionally vulnerable login route and its upstream
  `vuln-code-snippet` marker. It was not generated from repoauditor output.

This public snapshot may be analyzed with a hosted model. Proprietary code must never be added
to this corpus or sent to hosted models without explicit authorization.

Materialize with `python tests/fixtures/materialize_public_corpus.py <clone-cache> --fetch`.
