# Backstage: catalog & TechDocs

Myrmex Hive ships a Software Catalog descriptor and MkDocs config so it can be
onboarded into an internal developer portal.

## What's registered

`catalog-info.yaml` at the repo root declares two entities:

| Entity | Kind | Notes |
|---|---|---|
| `myrmex-hive` | Component | `type: service`, `lifecycle: production`. Provides the API below. |
| `myrmex-mcp` | API | `type: mcp`. Its `definition` is `$text`-inlined from `server.json`. |

The API definition is **inlined, not copied**. `server.json` is the manifest
published to the public MCP registry and is schema-validated in CI (see
[MCP registry](MCP_REGISTRY.md)), so the catalog entry cannot drift from the
real interface.

There is deliberately no `openapi` entity for the REST API. Writing one by hand
would create a fourth spec that nothing validates against the actual routes —
and hand-maintained lists have silently drifted three times in this repo
already. If you need it, generate it from the routes rather than typing it.

## Registering

Point Backstage at the descriptor — from the UI, **Create → Register existing
component**, with:

```
https://github.com/olafkfreund/myrmex-hive/blob/main/catalog-info.yaml
```

Or declare it in a `Location` entity in your Backstage config:

```yaml
catalog:
  locations:
    - type: url
      target: https://github.com/olafkfreund/myrmex-hive/blob/main/catalog-info.yaml
```

Validate before registering (this is what CI cannot do for you, since it needs
your Backstage instance):

```bash
# via the Backstage catalog MCP server / API
curl -X POST "$BACKSTAGE_URL/api/catalog/analyze-location" \
  -H 'Content-Type: application/json' \
  -d '{"location":{"type":"url","target":"https://github.com/olafkfreund/myrmex-hive/blob/main/catalog-info.yaml"}}'
```

Both entities were validated against a live Backstage catalog during #106 —
`isValid: true`.

## TechDocs

`mkdocs.yml` at the repo root drives the Docs tab, wired via the
`backstage.io/techdocs-ref: dir:.` annotation on the Component.

Build it exactly as CI does:

```bash
pip install mkdocs-techdocs-core
mkdocs build --strict
```

`--strict` turns broken internal links and dangling nav entries into failures.

### Two rules for docs in this repo

**Every `docs/**.md` must be in `mkdocs.yml`'s `nav`.** A doc missing from the
nav still builds — `--strict` only logs an `INFO` line and exits 0 — but it
never renders in Backstage. `TestTechDocsNavCoversEveryDoc` fails the build
instead, since a doc nobody can find is indistinguishable from a doc that was
never written.

**Links must not escape `docs/`.** `../README.md` resolves on GitHub but breaks
the TechDocs build, because MkDocs only knows about files under `docs_dir`. Use
an absolute `https://github.com/...` URL, which works in both places.

`docs/announce/` (launch/marketing drafts) is excluded via `exclude_docs` and is
legitimately absent from the nav; `excludedDocPrefixes` in the test mirrors that.

## Landing page

`docs/index.md` is a short landing page that **links** to the real docs. It
deliberately does not restate the README: an earlier attempt
([PR #5](https://github.com/olafkfreund/myrmex-hive/pull/5)) copied the README
into `docs/index.md`, and it was stale within weeks. The README stays the single
source for the overview.
