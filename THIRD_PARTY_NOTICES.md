# Third-party notices

RepoAuditor's original source is licensed under the root [MIT License](LICENSE).
That license does not relicense third-party fixture excerpts. The following
materials retain their upstream terms.

## OWASP Benchmark for Python

`tests/fixtures/owasp_benchmark_py/snapshot/` contains a selected, unmodified
subset of OWASP Benchmark for Python version 0.1 at commit
`f1291485808b66e20ddb6b01b10dc71b3df8c8ba`.

- Upstream: https://github.com/OWASP-Benchmark/BenchmarkPython
- License: GNU General Public License, version 3
- License text: https://github.com/OWASP-Benchmark/BenchmarkPython/blob/f1291485808b66e20ddb6b01b10dc71b3df8c8ba/LICENSE

The retained source headers identify the upstream copyright and license. Changes
to this subset, if any, must remain clearly identified and distributed under its
applicable GPLv3 terms.

## Gunicorn

`tests/fixtures/cve_gunicorn_smuggling/snapshot/gunicorn/http/message.py` is an
unmodified excerpt from Gunicorn 21.2.0.

- Upstream: https://github.com/benoitc/gunicorn
- License: MIT
- License text: https://github.com/benoitc/gunicorn/blob/21.2.0/LICENSE

The file retains its upstream license header. Its inclusion does not transfer
RepoAuditor's copyright to that excerpt.

## Acquisition metadata

Other test-corpus entries that name third-party projects retain metadata,
expected-result descriptions, and pinned identities only. Their generated source
snapshots are ignored and are not redistributed by this repository. See
`tests/fixtures/README.md` for provenance and license information.
