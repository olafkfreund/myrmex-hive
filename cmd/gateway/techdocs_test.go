package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// docs/*.md are rendered by BOTH MkDocs (TechDocs) and Jekyll (the public
// site at myrmex-hive.freundcloud.com), so they may only use syntax both
// understand. MkDocs-Material admonitions (`!!! note`, `??? tip`) are the
// trap: MkDocs draws a styled callout, Jekyll prints the marker as literal
// text and renders the indented body as a code block with raw markdown links
// inside it. That shipped to the live site and looked broken.
//
// Use a blockquote instead — both renderers handle it.

// escapedPipeInCodeSpan matches a `\|` occurring between backticks.
var escapedPipeInCodeSpan = regexp.MustCompile("`[^`]*\\\\\\|[^`]*`")

func TestDocsAvoidMkDocsOnlyAdmonitions(t *testing.T) {
	entries, err := os.ReadDir("../../docs")
	if err != nil {
		t.Fatalf("cannot read docs/: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		path := filepath.Join("../../docs", e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("cannot read %s: %v", path, err)
			continue
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "!!! ") || strings.HasPrefix(line, "??? ") {
				t.Errorf("docs/%s:%d uses a MkDocs-only admonition, which Jekyll renders as "+
					"literal text on the public site. Use a blockquote (\"> **Note.** …\").\n  %s",
					e.Name(), i+1, line)
			}
			// `a\|b` inside a table: the backslash is NOT unescaped inside a
			// code span, so BOTH renderers print a literal "\|". Separate the
			// alternatives with "/" instead.
			if escapedPipeInCodeSpan.MatchString(line) {
				t.Errorf("docs/%s:%d escapes a pipe inside a code span; both renderers print the "+
					"backslash literally. Use \"/\" to separate alternatives.\n  %s",
					e.Name(), i+1, line)
			}
		}
	}
}

// A doc missing from mkdocs.yml's nav is invisible in Backstage while looking
// perfectly fine in the repo — nobody notices until someone goes looking for a
// page that was never published. This repo has been bitten three times by
// hand-maintained lists that nothing enforced (server.json #102, /api/config
// redaction #131, and the metrics/dashboard pairing #99 pre-empted), so the nav
// gets the same treatment.
const (
	mkdocsPath = "../../mkdocs.yml"
	docsDir    = "../../docs"
)

// navEntryRe pulls the target out of a "  - Title: FILE.md" nav line.
var navEntryRe = regexp.MustCompile(`^\s*-\s+[^:]+:\s*(\S+\.md)\s*$`)

// navTargets returns the set of .md files referenced by mkdocs.yml's nav.
func navTargets(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(mkdocsPath)
	if err != nil {
		t.Fatalf("read mkdocs.yml: %v", err)
	}

	targets := map[string]bool{}
	inNav := false
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "nav:") {
			inNav = true
			continue
		}
		// A new top-level key ends the nav block.
		if inNav && len(line) > 0 && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "-") {
			inNav = false
		}
		if !inNav {
			continue
		}
		if m := navEntryRe.FindStringSubmatch(line); m != nil {
			targets[m[1]] = true
		}
	}
	if len(targets) == 0 {
		t.Fatal("no nav entries parsed from mkdocs.yml; did the nav format change?")
	}
	return targets
}

// excludedDocPrefixes mirrors mkdocs.yml's `exclude_docs`. docs/announce/ is
// launch/marketing copy, not product documentation, and must not render in
// Backstage - so it is legitimately absent from the nav.
var excludedDocPrefixes = []string{"announce/"}

// docsOnDisk returns every .md file under docs/, RECURSIVELY and relative to
// docs/ - matching how mkdocs addresses nav targets. Walking rather than
// globbing "*.md" matters: a doc added in a subdirectory would otherwise be
// missed here AND only produce an INFO line from `mkdocs build --strict`, so it
// would silently never render.
func docsOnDisk(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	err := filepath.WalkDir(docsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".md") {
			return nil
		}
		rel, err := filepath.Rel(docsDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		for _, prefix := range excludedDocPrefixes {
			if strings.HasPrefix(rel, prefix) {
				return nil
			}
		}
		out[rel] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("no docs found; wrong path?")
	}
	return out
}

// Every doc must appear in the nav, or it never renders in Backstage.
//
// `mkdocs build --strict` does NOT cover this: a doc missing from the nav is
// only an INFO line and the build still exits 0 (verified). It DOES fail on a
// dangling nav entry, which the sibling test below duplicates cheaply so both
// directions are caught in `go test` without a Python toolchain.
func TestTechDocsNavCoversEveryDoc(t *testing.T) {
	nav := navTargets(t)
	docs := docsOnDisk(t)

	var missing []string
	for doc := range docs {
		if !nav[doc] {
			missing = append(missing, doc)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("docs/ files missing from mkdocs.yml nav: %v\n\n"+
			"They exist in the repo but would NOT render in Backstage. Add each to the "+
			"nav: block in mkdocs.yml.", missing)
	}
}

// The converse: a nav entry pointing at a deleted/renamed file breaks the
// TechDocs build.
func TestTechDocsNavHasNoDanglingEntries(t *testing.T) {
	nav := navTargets(t)
	docs := docsOnDisk(t)

	var dangling []string
	for target := range nav {
		if !docs[target] {
			dangling = append(dangling, target)
		}
	}
	sort.Strings(dangling)
	if len(dangling) > 0 {
		t.Errorf("mkdocs.yml nav points at files that do not exist: %v\n\n"+
			"The TechDocs build fails on a dangling nav entry. Remove them or restore "+
			"the files.", dangling)
	}
}
