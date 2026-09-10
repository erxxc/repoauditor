# Zenodo release checklist

This checklist gates the first RepoAuditor archival release. Completing it does not itself
authorize a tag, GitHub Release, DOI reservation, Zenodo deposit, or publication.

## Metadata and provenance

- [x] MIT project license is present.
- [x] Third-party fixture licensing and non-relicensing boundaries are disclosed.
- [x] `CITATION.cff` and `.zenodo.json` agree on title, creator, version, license, and scope.
- [x] The independent PRNG Lattice Lab is linked without creating a runtime dependency.
- [x] Link Lattice Lab `v0.5.0` by version DOI `10.5281/zenodo.22697185`.
- [ ] Add the RepoAuditor DOI after reservation or first archive processing.
- [x] Set the final release date in `CITATION.cff`.

## Exact release archive

- [ ] Create the prospective `v0.1.0` archive from the reviewed release commit.
- [ ] Confirm the archive contains no `.envrc`, credentials, local audit database, acquired
      snapshots, raw scanner output, provider output, or ignored execution artifacts.
- [ ] Verify `LICENSE`, `SECURITY.md`, `THIRD_PARTY_NOTICES.md`, `CITATION.cff`,
      `.zenodo.json`, `README.md`, `pyproject.toml`, and `uv.lock` are present.
- [ ] Record the archive SHA-256 and file inventory in the release review.
- [ ] Run Gitleaks across full history and the release archive.

## Validation and publication

- [ ] Run the full offline non-live suite from the reviewed release commit.
- [ ] Validate `CITATION.cff` and `.zenodo.json` syntax and metadata agreement.
- [ ] Preview a draft in Zenodo Sandbox.
- [ ] Enable the GitHub repository in Zenodo only after the archive review passes.
- [ ] Create GitHub release `v0.1.0`; verify Zenodo processing and Software Heritage status.
- [ ] Confirm the version DOI, concept DOI, license, creators, related identifiers, and files
      before announcing the release.
