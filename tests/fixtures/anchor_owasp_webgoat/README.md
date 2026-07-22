# OWASP WebGoat benchmark anchor

- Kind: `benchmark` (deliberately vulnerable; not independent evaluation evidence)
- Materialization: pinned acquisition only; source is not redistributed in this repository.
- Upstream: https://github.com/WebGoat/WebGoat.git
- Commit: `5142935bf7c279882c3b0fc0ecec42c447de6fd5`
- License: GPL-2.0-or-later; upstream `LICENSE.txt` is retained when materialized.
- Ground truth: human review of the deliberately vulnerable SQL-injection lesson. It was not
  generated from repoauditor output.

Materialize with `python tests/fixtures/materialize_public_corpus.py <clone-cache> --fetch`.
This public source may be analyzed with a hosted model. Proprietary code must never be added or
sent to hosted models without explicit authorization.
