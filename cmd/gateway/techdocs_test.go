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
