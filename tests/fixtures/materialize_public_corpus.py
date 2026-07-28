"""Materialize the pinned public corpus on demand at exact verified commits.

This is intentionally not run by pytest. By default it uses verified local clones and never
fetches the network; `--fetch` explicitly allows cloning/fetching public upstreams. Generated
snapshots retain upstream license files and contain no `.git` metadata.
"""

from __future__ import annotations

import argparse
import io
import json
import subprocess
import tarfile
from pathlib import Path


PROJECTS = [
    dict(slug="lodash", project="Lodash", language="JavaScript", repo="https://github.com/lodash/lodash.git",
         cve="CVE-2020-8203", ghsa="GHSA-p6mc-m468-83gw", cwe="CWE-915", license="MIT",
         source_dataset="OpenSSF CVE Benchmark", pre="e7b28ea6cb17b4ca021e7c9d66218c8c89782f32",
         post="c84fe82760fb2d3e03a63379b297a1cc1a2fce12", file="lodash.js", line=3978,
         title="Prototype pollution in zipObjectDeep/baseSet", citation="nested[key]", severity="high"),
    dict(slug="parse_server", clone="parse-server", project="Parse Server", language="JavaScript",
         repo="https://github.com/parse-community/parse-server.git", cve="CVE-2020-5251",
         ghsa="GHSA-h4mf-75hf-67w4", cwe="CWE-89", license="BSD-3-Clause",
         source_dataset="OpenSSF CVE Benchmark", pre="bde8ab6d55e4da556d0e77eb29d4953ca34eeace",
         post="3a3a5eee5ffa48da1352423312cb767de14de269", file="src/RestQuery.js", line=667,
         title="Query injection through non-string request values", citation="this.restWhere", severity="high"),
    dict(slug="serialize_javascript", clone="serialize-javascript", project="serialize-javascript",
         language="JavaScript", repo="https://github.com/yahoo/serialize-javascript.git",
         cve="CVE-2019-16769", ghsa="GHSA-h9rv-jmmf-4pgx", cwe="CWE-79", license="BSD-3-Clause",
         source_dataset="OpenSSF CVE Benchmark", pre="3bab6dee8db7317310a97af5d28f0f0479d21930",
         post="16a68ab53d9626fc7c942b48a1163108fcd184c8", file="index.js", line=191,
         title="XSS through unsafe regular-expression serialization",
         citation="regexps[valueIndex].toString()", severity="high"),
    dict(slug="django", project="Django", language="Python", repo="https://github.com/django/django.git",
         cve="CVE-2021-31542", ghsa="GHSA-rxjp-mfm9-w4wr", cwe="CWE-22", license="BSD-3-Clause",
         source_dataset="CVEfixes v1.0.8 scope; independently verified", pre="7f1b088ab4a4342a87a11496096471703994a006",
         post="04ac1624bdc2fa737188401757cf95ced122d26d", file="django/core/files/storage.py", line=101,
         title="Path traversal through unsanitized uploaded filenames",
         citation="os.path.normpath(os.path.join(dirname", severity="high"),
    dict(slug="aiohttp", project="aiohttp", language="Python", repo="https://github.com/aio-libs/aiohttp.git",
         cve="CVE-2024-23334", ghsa="GHSA-5h86-8mv2-jq9f", cwe="CWE-22", license="Apache-2.0",
         source_dataset="CVEfixes v1.0.8 scope; independently verified", pre="33ccdfb0a12690af5bb49bda2319ec0907fa7827",
         post="1c335944d6a8b1298baf179b7c0b3069f10c514b", file="aiohttp/web_urldispatcher.py", line=643,
         title="Directory traversal when static resources follow symlinks",
         citation="self._directory.joinpath(filename).resolve()", severity="high"),
    dict(slug="commons_text", clone="commons-text", project="Apache Commons Text", language="Java",
         repo="https://github.com/apache/commons-text.git", cve="CVE-2022-42889",
         ghsa="GHSA-599f-7c49-w659", cwe="CWE-94", license="Apache-2.0",
         source_dataset="CVEfixes v1.0.8 scope; independently verified", pre="1c0340694871183baf6e55376dd85c260e810bb0",
         post="b9b40b903e2d1f9935039803c9852439576780ea",
         file="src/main/java/org/apache/commons/text/lookup/DefaultStringLookup.java", line=93,
         title="Code execution through dangerous default interpolators",
         citation="SCRIPT(StringLookupFactory.KEY_SCRIPT", severity="critical"),
    dict(slug="jspwiki", project="Apache JSPWiki", language="Java", repo="https://github.com/apache/jspwiki.git",
         cve="CVE-2019-10090", ghsa="GHSA-g6ww-2x43-h963", cwe="CWE-79", license="Apache-2.0",
         source_dataset="OpenSSF CVE Benchmark; also within CVEfixes scope",
         pre="447b5a634dfb6adcc7ff28181cb174aaa1920577", post="139746f7c25b84049437d1d9eed9456446a08bf7",
         file="jspwiki-war/src/main/scripts/moo-extend/Element.Extend.js", line=530,
         title="DOM XSS through unsafe transformed text insertion", citation="dummy.innerHTML = s", severity="high"),
    dict(slug="rack", project="Rack", language="Ruby", repo="https://github.com/rack/rack.git",
         cve="CVE-2023-27539", ghsa="GHSA-c6qg-cjj8-47qp", cwe="CWE-1333", license="MIT",
         source_dataset="ruby-advisory-db; independently verified with OSV/GHSA",
         pre="d6b5b2bab88f458fb048133604faebea952d8133", post="ee7919ea04303717858be1c3f16b406adc6d8cff",
         file="lib/rack/request.rb", line=573, title="ReDoS in HTTP Accept header parsing",
         citation="split(/\\s*,\\s*/)", severity="high"),
]

ANCHORS = [
    dict(fixture="anchor_owasp_juice_shop", clone="juice-shop",
         repo="https://github.com/juice-shop/juice-shop.git",
         commit="33518f5a0911e25d9df747b1e70fb7af279a755c"),
    dict(fixture="anchor_owasp_webgoat", clone="webgoat",
         repo="https://github.com/WebGoat/WebGoat.git",
         commit="5142935bf7c279882c3b0fc0ecec42c447de6fd5"),
    dict(fixture="anchor_owasp_railsgoat", clone="railsgoat",
         repo="https://github.com/OWASP/railsgoat.git",
         commit="0222f7da3406ba3ab637bc6d24ae9366b5f0a680"),
]


def archive(repo: Path, commit: str, destination: Path) -> None:
    payload = subprocess.run(
        ["git", "-C", str(repo), "archive", "--format=tar", commit],
        check=True, capture_output=True,
    ).stdout
    destination.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as bundle:
        bundle.extractall(destination, filter="data")


def ensure_clone(root: Path, clone_name: str, repo_url: str, commit: str, fetch: bool) -> Path:
    clone = root / clone_name
    if not clone.is_dir():
        if not fetch:
            raise SystemExit(f"missing local clone {clone}; rerun with --fetch")
        subprocess.run(
            ["git", "clone", "--filter=blob:none", "--no-checkout", repo_url, str(clone)],
            check=True,
        )
    present = subprocess.run(
        ["git", "-C", str(clone), "cat-file", "-e", f"{commit}^{{commit}}"],
        capture_output=True,
    ).returncode == 0
    if not present:
        if not fetch:
            raise SystemExit(f"clone {clone} lacks {commit}; rerun with --fetch")
        subprocess.run(["git", "-C", str(clone), "fetch", "origin", commit], check=True)
    return clone


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("clone_root", type=Path)
    parser.add_argument("--output", type=Path, default=Path(__file__).parent)
    parser.add_argument(
        "--include-training-acquisition",
        action="store_true",
        help=(
            "Also materialize the separately declared classifier-training acquisition "
            "cohort. These snapshots are never evaluation fixtures."
        ),
    )
    parser.add_argument(
        "--training-acquisition-only",
        action="store_true",
        help="Materialize only the non-evaluation classifier-training acquisition cohort.",
    )
    parser.add_argument(
        "--include-cve-positive-acquisition",
        action="store_true",
        help="Also materialize the frozen CVE-backed positive training cohort.",
    )
    parser.add_argument(
        "--cve-positive-acquisition-only",
        action="store_true",
        help="Materialize only the non-evaluation CVE-backed positive training cohort.",
    )
    parser.add_argument(
        "--fetch", action="store_true",
        help="Explicitly allow network clones/fetches for missing pinned commits.",
    )
    args = parser.parse_args()
    if not args.training_acquisition_only and not args.cve_positive_acquisition_only:
        for project in PROJECTS:
            clone = ensure_clone(
                args.clone_root, project.get("clone", project["slug"]),
                project["repo"], project["post"], args.fetch,
            )
            for variant, commit in (("pre", project["pre"]), ("post", project["post"])):
                repo_id = f"independent_{project['slug']}_{variant}"
                fixture = args.output / repo_id
                if (fixture / "snapshot").exists():
                    raise SystemExit(f"refusing to overwrite {fixture / 'snapshot'}")
                ensure_clone(
                    args.clone_root, project.get("clone", project["slug"]),
                    project["repo"], commit, args.fetch,
                )
                archive(clone, commit, fixture / "snapshot")
        for anchor in ANCHORS:
            fixture = args.output / anchor["fixture"]
            if (fixture / "snapshot").exists():
                raise SystemExit(f"refusing to overwrite {fixture / 'snapshot'}")
            clone = ensure_clone(
                args.clone_root, anchor["clone"], anchor["repo"], anchor["commit"], args.fetch
            )
            archive(clone, anchor["commit"], fixture / "snapshot")
    if args.include_training_acquisition or args.training_acquisition_only:
        manifest_path = Path(__file__).with_name("training_acquisition_cohort.json")
        manifest = json.loads(manifest_path.read_text())
        if manifest.get("evaluation_eligible") is not False:
            raise SystemExit("training acquisition manifest must be evaluation_eligible=false")
        for project in manifest["projects"]:
            fixture = args.output / f"acquisition_{project['slug']}"
            if (fixture / "snapshot").exists():
                raise SystemExit(f"refusing to overwrite {fixture / 'snapshot'}")
            clone = ensure_clone(
                args.clone_root,
                project["slug"],
                project["repository"],
                project["pinned_commit"],
                args.fetch,
            )
            archive(clone, project["pinned_commit"], fixture / "snapshot")
    if args.include_cve_positive_acquisition or args.cve_positive_acquisition_only:
        manifest_path = Path(__file__).with_name("cve_positive_acquisition_cohort.json")
        manifest = json.loads(manifest_path.read_text())
        if manifest.get("evaluation_eligible") is not False:
            raise SystemExit("CVE-positive acquisition manifest must be evaluation_eligible=false")
        for project in manifest["projects"]:
            clone = ensure_clone(
                args.clone_root,
                project["slug"],
                project["repository"],
                project["fixed_commit"],
                args.fetch,
            )
            for variant, commit in (
                ("pre", project["vulnerable_commit"]),
                ("post", project["fixed_commit"]),
            ):
                fixture = args.output / f"acquisition_cve_{project['slug']}_{variant}"
                if (fixture / "snapshot").exists():
                    raise SystemExit(f"refusing to overwrite {fixture / 'snapshot'}")
                ensure_clone(
                    args.clone_root,
                    project["slug"],
                    project["repository"],
                    commit,
                    args.fetch,
                )
                archive(clone, commit, fixture / "snapshot")


if __name__ == "__main__":
    main()
