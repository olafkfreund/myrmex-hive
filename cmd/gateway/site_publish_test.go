package main

// Guards what the public Jekyll site publishes.
//
// Jekyll copies EVERY top-level path that _config.yml does not exclude into
// the built site, and renders any markdown with front matter as a page. The
// failure mode is silent: you add a directory to the repo and it quietly
// appears on myrmex-hive.freundcloud.com.
//
// That is not hypothetical. Before this guard the live site was serving the
// internal CLAUDE.md as a web page, two unpublished marketing drafts, and 49
// vendored Go dependency pages — 49 of 73 total pages and ~21MB of a 23MB
// site. All three returned HTTP 200 in production. Nobody had noticed.
//
// So every top-level directory must be a DELIBERATE choice: either excluded,
// or named here as something the website is meant to carry.
//
// The exclude block is a flat YAML list, so it is scanned with the stdlib
// rather than pulling in a YAML dependency for a test — this repo hand-writes
// its Prometheus exposition for the same reason.

import (
	"os"
	"strings"
	"testing"
)

// publishedDirs are the top-level directories the public site is MEANT to
// serve. Adding to this list is a decision to publish, not a formality.
var publishedDirs = map[string]bool{
	"_posts":   true, // blog posts
	"_layouts": true, // templates, not served directly
	"_site":    true, // local build output
	"assets":   true, // css, images
	"blog":     true, // blog index
	"docs":     true, // operator docs, also rendered by TechDocs
}

// siteExcludes returns the entries of the `exclude:` list in _config.yml.
func siteExcludes(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile("../../_config.yml")
	if err != nil {
		t.Fatalf("cannot read _config.yml: %v", err)
	}

	out := map[string]bool{}
	inExclude := false
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "exclude:") {
			inExclude = true
			continue
		}
		if !inExclude {
			continue
		}
		trimmed := strings.TrimSpace(line)
		// A new top-level key ends the list; blank lines and comments do not.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(trimmed, "- ") {
			break
		}
		item := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
		if i := strings.Index(item, " #"); i >= 0 { // strip trailing comment
			item = strings.TrimSpace(item[:i])
		}
		out[strings.TrimSuffix(item, "/")] = true
	}

	if len(out) == 0 {
		t.Fatal("parsed zero exclude entries from _config.yml — the guard is not guarding anything")
	}
	return out
}

func TestSiteExcludesEverythingNotMeantToBePublished(t *testing.T) {
	excluded := siteExcludes(t)

	entries, err := os.ReadDir("../..")
	if err != nil {
		t.Fatalf("cannot read repo root: %v", err)
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		// Dotted directories (.git, .github) are never published by Jekyll.
		if strings.HasPrefix(name, ".") {
			continue
		}
		if excluded[name] || publishedDirs[name] {
			continue
		}
		t.Errorf("top-level directory %q is neither excluded in _config.yml nor listed as "+
			"published — Jekyll will copy it into the PUBLIC site at "+
			"myrmex-hive.freundcloud.com. Add it to `exclude:` in _config.yml, or to "+
			"publishedDirs in this test if the website really should serve it.", name)
	}
}

// The specific paths that were leaking. Losing any of these again republishes
// internal or third-party content, so they are pinned by name rather than left
// to the general rule above.
func TestSiteExcludesTheKnownLeaks(t *testing.T) {
	excluded := siteExcludes(t)

	for _, leak := range []struct{ path, why string }{
		{"vendor", "49 third-party dependency pages, two thirds of the built site"},
		{"CLAUDE.md", "internal agent instructions, published as a web page"},
		{"docs/announce", "unpublished marketing drafts, also excluded from TechDocs"},
	} {
		if !excluded[leak.path] {
			t.Errorf("_config.yml no longer excludes %q — %s", leak.path, leak.why)
		}
	}
}
