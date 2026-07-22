# aiohttp post-fix pinned acquisition

- Kind: `independent`
- Materialization: pinned acquisition only; source is not redistributed in this repository.
- Language: Python
- Upstream: https://github.com/aio-libs/aiohttp.git
- Commit: `1c335944d6a8b1298baf179b7c0b3069f10c514b`
- Pair: `33ccdfb0a12690af5bb49bda2319ec0907fa7827` (vulnerable) / `1c335944d6a8b1298baf179b7c0b3069f10c514b` (patched)
- Advisory: CVE-2024-23334 / GHSA-5h86-8mv2-jq9f
- License: Apache-2.0 (upstream license file retained when materialized)
- Provenance: CVEfixes v1.0.8 scope; independently verified plus OSV and human review of the fix diff.

The advisory and patch are reviewer evidence, not tool-generated labels. This is public source; proprietary code must never be added or sent to a hosted model.
