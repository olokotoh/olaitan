// Command olaitan-lint mechanically enforces the two canonical-name
// conventions the architecture relies on (docs/patterns.md sections 1-2,
// docs/contributing.md "Forbidden patterns"): a NATS subject must come from
// internal/subjects/ and a Redis key must come from internal/keys/, never
// from a string literal at a call site. It scans the Go source tree with
// go/ast and reports any string literal that matches a canonical NATS-subject
// shape outside internal/subjects/ or a canonical Redis-key shape outside
// internal/keys/, failing CI (non-zero exit) on any surviving finding.
//
// WHY go/ast and not a regex over raw bytes: a comment that MENTIONS a
// subject (for example the `// ... "AUDIT.* 365 d"` retention notes in
// internal/nats/streams.go) is not an *ast.BasicLit, so the AST walk never
// sees it. Only real string-literal AST nodes are candidates.
//
// DETECTION HEURISTIC (Story 6.5 decision, recorded in the story Dev Notes).
// The patterns are DERIVED from the canonical lists:
//
//   - Subjects (internal/subjects/subjects.go): the lower-case operational
//     families all begin `olaitan.` and continue with a KNOWN second segment
//     (events. / correlated. / state. / threats. / evidence. / health.), plus
//     the exact `olaitan.events.normalised`; the dotted-UPPER published
//     contract families are AUDIT. / OVERRIDES. / INCIDENTS. / REPORTS. /
//     INVESTIGATIONS. / THREATS.
//   - Keys (internal/keys/keys.go): the family prefixes are baseline: /
//     checkpoint: / state: / evidence: / health: / fsm: / override:.
//
// Two false-positive guards make the heuristic precise (both verified against
// the real tree, which is WHY the existing code passes, AC4):
//
//  1. The `olaitan.` arm matches ONLY the enumerated second segments, so the
//     Kubernetes annotation domain `olaitan.io/...` (the `/` is never legal in
//     a subject) and the envelope schema-version `olaitan.eval.capture.
//     envelope.v1` do NOT match.
//  2. A key match requires the rune immediately after the family colon to be a
//     key-token rune [A-Za-z0-9_.{-], NOT a space. This separates a real key
//     (`baseline:ns:pod:metrics`, `fsm:{workload_id}`) from the ubiquitous
//     `package: message` error-string idiom (`"baseline: store: ..."`,
//     `"health: serve: %w"`), which always has a space after the colon.
//
// The match is anchored at the START of the literal: the forbidden pattern is
// hard-coding a subject AS the subject at a call site, not mentioning a subject
// name mid-prose. Test files (*_test.go) are out of default scope: the subjects
// conformance suite pins every constant to its literal, and integration tests
// drive REAL subjects through embedded NATS by design (NFR35). Pass
// -include-tests to scan them too.
//
// ESCAPE HATCH: a `//olaitan-lint:allow subject <reason>` or
// `//olaitan-lint:allow key <reason>` comment on the same line as (or the line
// immediately above) a flagged literal suppresses that one finding. The reason
// is MANDATORY, so the hatch cannot silently mute a finding; the suppression is
// greppable and auditable rather than a hidden heuristic carve-out.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// subjectsPkgDir and keysPkgDir are the canonical packages whose literals are
// exempt from the corresponding check (a subject literal inside
// internal/subjects/ is the source of truth, not a violation; likewise keys).
const (
	subjectsPkgDir = "internal/subjects"
	keysPkgDir     = "internal/keys"
)

// subjectLowerPrefixes are the enumerated `olaitan.<segment>` prefixes that a
// real operational subject begins with. Enumerating the known second segments
// (rather than a bare `olaitan.` prefix) is the guard that excludes the
// `olaitan.io/...` annotation domain and the `olaitan.eval.capture...` schema
// version, which are legitimate non-subject literals.
var subjectLowerPrefixes = []string{
	"olaitan.events.",     //olaitan-lint:allow subject this is the canonical-prefix derivation, not a call-site subject
	"olaitan.correlated.", //olaitan-lint:allow subject this is the canonical-prefix derivation, not a call-site subject
	"olaitan.state.",      //olaitan-lint:allow subject this is the canonical-prefix derivation, not a call-site subject
	"olaitan.threats.",    //olaitan-lint:allow subject this is the canonical-prefix derivation, not a call-site subject
	"olaitan.evidence.",   //olaitan-lint:allow subject this is the canonical-prefix derivation, not a call-site subject
	"olaitan.health.",     //olaitan-lint:allow subject this is the canonical-prefix derivation, not a call-site subject
}

// subjectUpperPrefixes are the dotted-UPPER published-contract subject
// families. A literal matches only when one of these is followed by a
// subject-token rune (an UPPER family letter, a lower-case token, or a `{`
// dynamic-segment opener), so a bare word like "AUDITED" does not match.
var subjectUpperPrefixes = []string{
	"AUDIT.",
	"OVERRIDES.",
	"INCIDENTS.",
	"REPORTS.",
	"INVESTIGATIONS.",
	"THREATS.",
}

// keyPrefixes are the canonical Redis key-family prefixes from
// internal/keys/keys.go.
var keyPrefixes = []string{
	"baseline:",
	"checkpoint:",
	"state:",
	"evidence:",
	"health:",
	"fsm:",
	"override:",
}

// finding is one reported canonical-name violation.
type finding struct {
	file     string
	line     int
	col      int
	category string // "subject" or "key"
	literal  string // the unquoted offending literal
}

func main() {
	includeTests := flag.Bool("include-tests", false, "also scan *_test.go files (off by default: NFR35 integration tests legitimately drive real subjects)")
	flag.Parse()

	roots := flag.Args()
	if len(roots) == 0 {
		roots = []string{"."}
	}

	findings, err := run(roots, *includeTests)
	if err != nil {
		fmt.Fprintln(os.Stderr, "olaitan-lint:", err)
		os.Exit(2)
	}
	if len(findings) == 0 {
		return
	}
	for _, f := range findings {
		fmt.Printf("%s:%d:%d: %s literal not allowed outside %s/: %q\n",
			f.file, f.line, f.col, f.category, exemptDirFor(f.category), f.literal)
	}
	fmt.Fprintf(os.Stderr, "olaitan-lint: %d canonical-name violation(s) found\n", len(findings))
	os.Exit(1)
}

// exemptDirFor names the canonical package a given category must live in.
func exemptDirFor(category string) string {
	if category == "key" {
		return keysPkgDir
	}
	return subjectsPkgDir
}

// run walks every root, scans each candidate Go file, and returns the findings
// in stable file:line:col order (so the CI exit is reproducible).
func run(roots []string, includeTests bool) ([]finding, error) {
	var findings []finding
	seen := map[string]bool{}

	for _, root := range roots {
		// Accept a trailing `/...` (the go-tooling package-pattern idiom) by
		// treating it as "walk this directory tree".
		root = strings.TrimSuffix(root, string(filepath.Separator)+"...")
		root = strings.TrimSuffix(root, "/...")
		if root == "" {
			root = "."
		}

		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if skipDir(d.Name()) {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			if !includeTests && strings.HasSuffix(path, "_test.go") {
				return nil
			}
			if seen[path] {
				return nil
			}
			seen[path] = true

			fileFindings, ferr := scanFile(path)
			if ferr != nil {
				return ferr
			}
			findings = append(findings, fileFindings...)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].file != findings[j].file {
			return findings[i].file < findings[j].file
		}
		if findings[i].line != findings[j].line {
			return findings[i].line < findings[j].line
		}
		return findings[i].col < findings[j].col
	})
	return findings, nil
}

// skipDir reports whether the walk should not descend into a directory. The
// .git tree, build output (bin/), and the gitignored chart build artefacts
// (deploy/helm/olaitan/{charts,files}) are not Go source we own.
func skipDir(name string) bool {
	switch name {
	case ".git", "bin", "vendor", "charts", "files", "node_modules", "testdata":
		return true
	}
	return false
}

// scanFile parses one Go file and returns the canonical-name findings in it,
// honouring inline //olaitan-lint:allow directives.
func scanFile(path string) ([]finding, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	allows, derr := allowDirectives(fset, f)
	if derr != nil {
		return nil, fmt.Errorf("%s: %w", path, derr)
	}

	rel := relPath(path)
	exemptSubject := withinDir(rel, subjectsPkgDir)
	exemptKey := withinDir(rel, keysPkgDir)

	var out []finding
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		val, uerr := strconv.Unquote(lit.Value)
		if uerr != nil {
			// A raw string literal or anything Unquote cannot handle is not a
			// candidate subject/key (those are plain double-quoted strings).
			return true
		}
		pos := fset.Position(lit.Pos())

		if !exemptSubject && matchesSubject(val) {
			if !allows[pos.Line]["subject"] {
				out = append(out, finding{file: rel, line: pos.Line, col: pos.Column, category: "subject", literal: val})
			}
		}
		if !exemptKey && matchesKey(val) {
			if !allows[pos.Line]["key"] {
				out = append(out, finding{file: rel, line: pos.Line, col: pos.Column, category: "key", literal: val})
			}
		}
		return true
	})
	return out, nil
}

// matchesSubject reports whether s is a canonical NATS-subject literal. The
// match is anchored at the start of s.
func matchesSubject(s string) bool {
	if s == "olaitan.events.normalised" { //olaitan-lint:allow subject canonical-list derivation, not a call-site subject
		return true
	}
	for _, p := range subjectLowerPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	for _, p := range subjectUpperPrefixes {
		if strings.HasPrefix(s, p) {
			rest := s[len(p):]
			if rest == "" {
				continue
			}
			r := rest[0]
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || r == '{' {
				return true
			}
		}
	}
	return false
}

// matchesKey reports whether s is a canonical Redis-key literal. A match
// requires the rune immediately after the family colon to be a key-token rune
// (NOT a space), which excludes the `package: message` error-string idiom.
func matchesKey(s string) bool {
	for _, p := range keyPrefixes {
		if !strings.HasPrefix(s, p) {
			continue
		}
		rest := s[len(p):]
		if rest == "" {
			continue
		}
		if isKeyTokenByte(rest[0]) {
			return true
		}
	}
	return false
}

// isKeyTokenByte reports whether b can legally follow a key-family colon in a
// real key: the internal/keys allow-list [A-Za-z0-9_.-], plus `{` for the
// workload-id dynamic segment. A space (the error-string discriminator) is not
// a key-token byte.
func isKeyTokenByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z':
		return true
	case b >= 'A' && b <= 'Z':
		return true
	case b >= '0' && b <= '9':
		return true
	case b == '_' || b == '.' || b == '-' || b == '{':
		return true
	}
	return false
}

// allowDirectives builds a map from line number to the set of categories
// suppressed on that line by an //olaitan-lint:allow <category> <reason>
// comment. A directive applies to the literal on its OWN line (trailing
// comment) or to the line immediately below it (leading comment). A directive
// missing a reason, or naming an unknown category, is an error so the escape
// hatch cannot be misused to silently mute a finding.
func allowDirectives(fset *token.FileSet, f *ast.File) (map[int]map[string]bool, error) {
	allows := map[int]map[string]bool{}
	add := func(line int, cat string) {
		if allows[line] == nil {
			allows[line] = map[string]bool{}
		}
		allows[line][cat] = true
	}

	for _, cg := range f.Comments {
		for _, c := range cg.List {
			text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
			if !strings.HasPrefix(text, "olaitan-lint:allow") {
				continue
			}
			rest := strings.TrimSpace(strings.TrimPrefix(text, "olaitan-lint:allow"))
			fields := strings.Fields(rest)
			if len(fields) == 0 {
				return nil, fmt.Errorf("olaitan-lint:allow directive missing a category (want `subject` or `key`)")
			}
			cat := fields[0]
			if cat != "subject" && cat != "key" {
				return nil, fmt.Errorf("olaitan-lint:allow unknown category %q (want `subject` or `key`)", cat)
			}
			if reason := strings.TrimSpace(strings.TrimPrefix(rest, cat)); reason == "" {
				return nil, fmt.Errorf("olaitan-lint:allow %s directive requires a reason", cat)
			}
			line := fset.Position(c.Pos()).Line
			// Suppress on the directive's own line (trailing comment) and the
			// next line (leading comment above the literal).
			add(line, cat)
			add(line+1, cat)
		}
	}
	return allows, nil
}

// relPath cleans a walked path to a forward-slash relative form for stable,
// platform-independent reporting and directory-exemption checks.
func relPath(p string) string {
	return filepath.ToSlash(filepath.Clean(p))
}

// withinDir reports whether the cleaned relative path rel is inside dir.
func withinDir(rel, dir string) bool {
	dir = filepath.ToSlash(filepath.Clean(dir))
	return rel == dir || strings.Contains(rel, "/"+dir+"/") || strings.HasPrefix(rel, dir+"/")
}
