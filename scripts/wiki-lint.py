#!/usr/bin/env python3
"""Drift guard for the project wiki (#873).

The wiki is a separate repository with no pull-request gate, so it can drift from
the code silently — exactly how the Architecture pages once claimed a module split
that was already done. This lints a local wiki checkout against the code tree and
fails on the drift classes the consolidation (#871/#872) removed, so they cannot
creep back:

  1. Broken internal anchors  — a [text](Page#anchor) whose page or heading is gone.
  2. file:line citations      — pinning `Something.cs:123` in prose; the rule is to
                                cite modules and type names, never paths that move.
  3. Dead source links        — a blob/<ref>/<path> link to a file not in the tree.

Usage: wiki-lint.py <wiki_dir> <code_repo_dir>
Exit code 1 (with a report) on any finding; 0 when clean.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# GitHub heading-slug rules: lowercase, drop everything that is not a word char,
# space, or hyphen, then spaces -> hyphens. Good enough for our own headings.
_SLUG_STRIP = re.compile(r"[^\w\- ]")


def slugify(heading: str) -> str:
    text = heading.strip().lower()
    text = _SLUG_STRIP.sub("", text)
    return text.replace(" ", "-")


def page_slug(md_path: Path) -> str:
    # Wiki links address a page by its filename with spaces/hyphens interchangeable.
    return md_path.stem.replace(" ", "-").lower()


def heading_slugs(text: str) -> set[str]:
    slugs: set[str] = set()
    for line in text.splitlines():
        m = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if m:
            slugs.add(slugify(m.group(1)))
    return slugs


_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
# A markdown link target we treat as an intra-wiki page reference: no scheme, not an
# anchor-only (#...) or a mailto, and not an absolute path.
_EXTERNAL = re.compile(r"^(https?:|mailto:|#|/)")


def check_anchors(wiki: Path) -> list[str]:
    pages = {page_slug(p): p for p in wiki.glob("*.md")}
    slugs_by_page = {s: heading_slugs(p.read_text(encoding="utf-8")) for s, p in pages.items()}
    findings: list[str] = []
    for src, path in pages.items():
        for target in _LINK.findall(path.read_text(encoding="utf-8")):
            target = target.strip()
            if _EXTERNAL.match(target):
                continue
            page, _, anchor = target.partition("#")
            key = page.replace(" ", "-").lower()
            if key not in pages:
                findings.append(f"{path.name}: link to unknown wiki page '{page}'")
                continue
            if anchor and slugify(anchor) not in slugs_by_page[key]:
                findings.append(f"{path.name}: broken anchor '#{anchor}' on page '{page}'")
    return findings


_FILELINE = re.compile(r"[\w./-]+\.cs:\d+")


def check_file_line_citations(wiki: Path) -> list[str]:
    findings: list[str] = []
    for path in wiki.glob("*.md"):
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for hit in _FILELINE.findall(line):
                findings.append(
                    f"{path.name}:{n}: file:line citation '{hit}' — cite the module/type, not a path that moves"
                )
    return findings


_BLOB = re.compile(r"github\.com/[^/]+/[^/]+/blob/[^/]+/([^)#\s]+)")


def check_dead_source_links(wiki: Path, code: Path) -> list[str]:
    findings: list[str] = []
    for path in wiki.glob("*.md"):
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for rel in _BLOB.findall(line):
                if not (code / rel).exists():
                    findings.append(f"{path.name}:{n}: dead source link '{rel}' (not in the code tree)")
    return findings


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    wiki, code = Path(sys.argv[1]), Path(sys.argv[2])
    findings = (
        check_anchors(wiki)
        + check_file_line_citations(wiki)
        + check_dead_source_links(wiki, code)
    )
    if findings:
        print(f"Wiki lint found {len(findings)} issue(s):\n")
        for f in findings:
            print(f"  - {f}")
        print("\nFix the wiki (or the citation rule in Coding-Standards) and re-run.")
        return 1
    print("Wiki lint: clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
