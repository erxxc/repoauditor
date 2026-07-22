# Parse Server pre-fix pinned acquisition

- Kind: `independent`
- Materialization: pinned acquisition only; source is not redistributed in this repository.
- Language: JavaScript
- Upstream: https://github.com/parse-community/parse-server.git
- Commit: `bde8ab6d55e4da556d0e77eb29d4953ca34eeace`
- Pair: `bde8ab6d55e4da556d0e77eb29d4953ca34eeace` (vulnerable) / `3a3a5eee5ffa48da1352423312cb767de14de269` (patched)
- Advisory: CVE-2020-5251 / GHSA-h4mf-75hf-67w4
- License: BSD-3-Clause (upstream license file retained when materialized)
- Provenance: OpenSSF CVE Benchmark plus OSV and human review of the fix diff.

The advisory and patch are reviewer evidence, not tool-generated labels. This is public source; proprietary code must never be added or sent to a hosted model.
