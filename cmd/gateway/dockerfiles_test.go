package main

// Guards the Dockerfiles against the single-file build bug.
//
// `go build -o gateway cmd/gateway/main.go` compiles ONLY that file and
// silently ignores every other file in the package. It works right up until
// the package grows a second file, then fails with undefined symbols that
// point nowhere near the real cause.
//
// This already burned the v1.0.1 release tag via .goreleaser.yaml's `main:`
// (fixed in #122, guarded there by a snapshot build). The identical bug sat in
// four Dockerfiles for weeks afterwards: cmd/gateway grew to eight files, so
// the compose stack could not build at all — invisible because local runs
// reused cached images and CI never builds these files.
//
// A static check rather than four `docker build`s: it catches this exact class
// for every Dockerfile at unit-test cost, and the expensive build would mostly
// re-prove the same thing.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// goBuildOfAFile matches a `go build` whose target is a .go FILE path rather
// than a package directory.
var goBuildOfAFile = regexp.MustCompile(`go build[^\n]*\s\S*\.go(\s|$)`)

func TestDockerfilesBuildPackagesNotFiles(t *testing.T) {
	dir := "../../Dockerfiles"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read %s: %v", dir, err)
	}

	checked := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("cannot read %s: %v", path, err)
			continue
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue // a comment explaining the rule is not a violation of it
			}
			if goBuildOfAFile.MatchString(line) {
				t.Errorf("%s:%d builds a FILE, not a package — this compiles only that one "+
					"file and silently ignores the rest of the package. Use ./cmd/<name>.\n  %s",
					path, i+1, strings.TrimSpace(line))
			}
		}
		checked++
	}

	if checked == 0 {
		t.Fatal("no Dockerfiles were checked — the guard is not actually guarding anything")
	}
	t.Logf("checked %d Dockerfiles", checked)
}
