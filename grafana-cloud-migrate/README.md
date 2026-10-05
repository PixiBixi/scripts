# grafana-cloud-migrate

Migrates a self-hosted Grafana to Grafana Cloud (or any other Grafana) through the
HTTP API: folders, dashboards, library panels, alert rules, contact points,
notification routing, annotations and playlists, rewriting datasource references
along the way. Dry-run by default: only the `apply`-style commands write to the
target.

The pitfalls behind each design choice are written up in
[Migrer Grafana vers Grafana Cloud](https://wiki.jdelgado.fr/monitoring/lgtm/grafana-cloud-migration/)
(French).

## Status

Built for one real migration, then generalised. Know what has actually run
against a live target before relying on it:

| Command | Exercised against a real target |
| --- | --- |
| `preflight`, `plan`, `alerts-plan` | yes |
| `apply`, `rollback` | yes |
| `alerts-apply`, `alerts-contacts`, `alerts-routing`, `alerts-rollback` | no, written from the API docs and the shape of source objects |
| `library-panels`, `annotations`, `playlists`, `prune` | no, dry-run only |

Run the untested ones with `--limit` or on a sandbox folder first, and keep the
rollback commands in reach.

Dashboard UIDs are preserved, so reruns are idempotent and existing permalinks
keep working.

## Install

Nothing to install: the script carries its dependencies inline (PEP 723).

```bash
./grafana_migrate.py --help          # runs via uv
```

For the test suite:

```bash
uv sync
uv run pytest -q
uv run ruff check .
```

## Credentials

Passed by environment only, never as flags.

| Variable | Fallbacks | Meaning |
| --- | --- | --- |
| `SRC_URL` | `GRAFANA_URL` | Source instance, e.g. `https://grafana.example.com` |
| `SRC_TOKEN` | `GRAFANA_TOKEN`, `GRAFANA_SERVICE_ACCOUNT_TOKEN` | Source service account token |
| `DST_URL` | none | Target instance, e.g. `https://<stack>.grafana.net`. Required |
| `DST_TOKEN` | none | Target service account token. Asked for interactively when unset |
| `GRAFANA_RPS` | | Client-side request ceiling per second, default `10`. `0` disables it |

The source falls back to the ambient `GRAFANA_*` variables, so a shell already
configured against the old instance needs only `DST_URL` and `DST_TOKEN`. When a
fallback is used, the script prints which variable it took the source from.

The target URL is required and printed on every run. It never falls back to an
ambient `GRAFANA_*` variable or to a default: no stale shell variable should be
able to become a write target by accident.

`DST_TOKEN` is never defaulted. When it is unset the script asks for it, with the
input hidden so it stays out of the scrollback and the shell history. Without a
terminal (CI) it exits rather than hanging on a prompt nobody can answer.

The target token must be a **service account token created inside the stack**
(`https://<stack>.grafana.net/org/serviceaccounts`), not a Cloud Access Policy
token from grafana.com: access policies do not authorize the Grafana HTTP API.

The tokens need `dashboards:read` + `datasources:read` on the source, and
`dashboards:write` + `folders:write` + `datasources:read` on the target.

## Commands

| Command | Writes to target | What it does |
| --- | --- | --- |
| `preflight` | no | Checks both instances, builds `out/datasource_map.csv` |
| `plan` | no | Builds every target payload under `out/dashboards/`, writes `out/plan.csv`, `out/blockers.csv` and `out/empty_after_drop.csv` |
| `apply` | yes | Creates folders, pushes dashboards, writes `out/rollback.json` |
| `relink` | with `--apply` | Repoints links to the old instance in dashboards already on the target, writes `out/relink.csv` |
| `prune` | with `--apply` | Deletes target dashboards this tool pushed that have gone from the source |
| `library-panels` | with `--apply` | Copies the library panels, keeping their uid. Reports only without `--apply` |
| `annotations` | with `--apply` | Copies hand-written dashboard annotations, skipping CI markers |
| `playlists` | with `--apply` | Copies the playlists |
| `alerts-plan` | no | Builds alert-rule payloads under `out/alerts/`, writes `out/alerts/plan.csv` and `groups.csv` |
| `alerts-apply` | yes | Pushes the alert rules, **paused**, one rule group at a time |
| `alerts-contacts` | yes | Copies the contact points with their secrets, source to target |
| `alerts-routing` | yes | Copies the templates, mute timings and notification policy tree |
| `alerts-rollback` | yes | Deletes the rule groups the last `alerts-apply` wrote, restores the routing |
| `rollback` | yes | Deletes everything the last `apply` created |

## Flags

| Flag | Commands | Default | Meaning |
| --- | --- | --- | --- |
| `--out` | all | `out` | Directory for reports and payloads |
| `--rebuild` | `preflight` | off | Discard an existing datasource map and rebuild it |
| `--folder` | `plan`, `apply`, `relink` | all | Restrict to this folder title. Repeatable |
| `--exclude` | `plan`, `apply` | none | Regex on folder or dashboard title. Repeatable |
| `--include-backups` | `plan`, `apply` | off | Do not skip the `Backups` folder |
| `--skip-empty` | `plan` | off | Skip dashboards whose every datasource was dropped |
| `--skip-duplicates` | `apply` | off | Leave dashboards already on the target under another uid alone |
| `--force` | `plan`, `alerts-plan` | off | Replan everything, ignoring what the last apply pushed |
| `--limit` | `plan`, `apply`, `relink` | `0` | Stop after N dashboards. `0` means no limit |
| `--src-host` | `relink` | host of `$SRC_URL` | Hostname of the old instance |
| `--namespace` | `relink` | `default`, or `$DST_NAMESPACE` | Target API namespace, `stacks-<stack id>` on Grafana Cloud |
| `--skip-blocked` | `apply` | off | Skip blocked dashboards instead of aborting |
| `--yes` / `-y` | `apply`, `rollback` | off | Do not ask for confirmation |

## Workflow

```bash
# Source picked up from GRAFANA_* when SRC_* are unset.
# Without DST_TOKEN the script asks for it.
export DST_URL=https://<stack>.grafana.net
export DST_TOKEN=glsa_...

./grafana_migrate.py preflight           # then fix out/datasource_map.csv by hand
./grafana_migrate.py plan --limit 20     # read out/plan.csv
./grafana_migrate.py apply --limit 20    # migrate a first batch
```

Drop `--limit` once a batch looks right. `plan` is safe to rerun at any time.

## The datasource map

`out/datasource_map.csv` is the source-to-target correspondence table. Each source
datasource is matched by uid, then by name and type, then by name alone. Anything
left over gets `method=UNRESOLVED` and an empty `dst_uid`.

Fill `dst_uid` in by hand and rerun `plan`: the row is then reported as `MANUAL`.

Write `DROP` in `dst_uid` to declare a datasource deliberately abandoned. Its
references are left untouched, the dashboards using it migrate instead of being
blocked, and they are listed in the `dropped` column. A dashboard that depends on
nothing else arrives empty and is listed in `out/empty_after_drop.csv`. Pass
`--skip-empty` to `plan` to leave those behind instead: a dashboard keeping even one
live panel, or one datasource template variable, is never counted as empty.

Delete the file (or pass `--rebuild` to `preflight`) to start over. `--rebuild`
rebuilds from the live instances, so it discards every `DROP` and every manual
edit: keep a copy if the decisions took work.

## Reading out/plan.csv

| Column | Meaning |
| --- | --- |
| `action` | `create`, `update`, `skip`, `DUPLICATE` or `BLOCKED` |
| `src_version` | The source dashboard version this plan was built from |
| `src_updated` | When the source dashboard was last saved, and by extension whether it is stale |
| `reason` | Why a `skip` was skipped |
| `rewritten` | References pointed at a new target uid |
| `already_correct` | References whose uid is identical on both sides |
| `template_refs` | References to a `${var}`, left untouched |
| `builtin_refs` | References to `grafana`, `-- Mixed --`, `__expr__`, left untouched |
| `inherited_default` | Null references, which follow the *target* default datasource |
| `unresolved` | Datasource exists on the source but has no target match. **Blocks** |
| `dangling` | Datasource absent from the source too: already broken, migrated as-is |
| `dropped` | Datasource marked `DROP` in the map: abandoned on purpose, migrated as-is |
| `duplicate_uid` | Uid of a dashboard already on the target with the same folder and title |
| `relinked` | Occurrences of the source hostname repointed to the target (links, text panels, descriptions) |
| `relinked_ds` | Source datasource uids pinned in those links (`var-<name>=<uid>`) remapped to the target uid |
| `goto_links` | `/goto/` short links to the source: instance-local, recreate them by hand |
| `warnings` | Library panels and legacy panel alerts, which this script does not migrate |

### Reruns only push what changed

`apply` records the source `version` of every dashboard it pushed in
`out/state.json`. The next `plan` compares each dashboard against that record and
marks anything still at the same version as `skip`, so a second run pushes only
what people actually edited.

Grafana bumps `version` on every save, so equality is a reliable "not touched".
Two limits are worth knowing. `/api/search` does not return the version, so `plan`
still fetches every dashboard: the saving is on writes, not on reads. And the
record describes the *source* only, so an edit made directly on the target is
invisible and its dashboard stays skipped. `--force` replans everything and is the
way out of both.

Losing `out/state.json` costs one redundant push, never a failure.

### Dashboards already on the target

A dashboard imported by hand earlier may sit on the target under a different uid.
The uid is what makes a rerun idempotent, so a uid-only check does not see it and
pushing ours would leave two dashboards with the same name in the same folder.

`plan` therefore also indexes the target by folder and title. A match under another
uid is reported as `DUPLICATE` in `out/duplicates.csv`, and `apply` refuses to run
until you either delete the target copies and rerun `plan`, or pass
`--skip-duplicates` to leave them alone. Titles repeating across different folders
are not collisions and are not reported.

`BLOCKED` rows make `apply` abort unless `--skip-blocked` is passed. Fix them in
the datasource map rather than skipping them: an unmapped datasource renders as an
empty panel, which is easy to miss.

## Links to the old instance

`plan` repoints every `https://<source host>/...` string of a dashboard to the target host, and remaps a source datasource uid pinned in such a link. For dashboards migrated before this existed, `relink` does the same on the target copy, so edits made on the target since are kept:

```bash
export DST_NAMESPACE=stacks-123456
./grafana_migrate.py relink --src-host grafana.example.com            # read out/relink.csv
./grafana_migrate.py relink --src-host grafana.example.com --apply
```

| `relink.csv` action | Meaning |
| --- | --- |
| `relink` | Saved with `--apply`, version note `relink: <source> -> <target>` |
| `skip` | Provisioned, or stored as schema v2: `/api/dashboards` would save it back as v1. Fix by hand |

A dashboard saved between the scan and the write fails with `412`: rerun.

## Rate limiting

Grafana Cloud rate-limits the HTTP API per org and returns `429`. The ceiling is
not published for the dashboard and folder endpoints, so the script does not
assume one: it self-throttles to `GRAFANA_RPS` requests per second, keeps writes
sequential, and retries `429` and `5xx` with exponential backoff that honours
`Retry-After`. `apply` prints how many `429` it absorbed; if that number is large,
lower `GRAFANA_RPS` and migrate in batches with `--limit`.

## Deleting on the source

A dashboard deleted on the source does not disappear from the target: `plan` lists
what exists on the source, so a deleted one produces no row and `apply` never sees
it. The two instances drift a little more with every cleanup.

```bash
./grafana_migrate.py prune            # reports only
./grafana_migrate.py prune --apply
```

`prune` deletes only dashboards that satisfy all three conditions: **this tool
pushed them**, they are still on the target, and they are gone from the source.

The first condition is the important one. The set of pushed uids comes from
`out/state.json`, falling back to `out/plan.csv` and `out/rollback.json`. A
dashboard created directly on the target is in no manifest, so `prune` cannot see
it. That is a property of how the candidate set is built, not a filter that could
be forgotten. It also means `prune` will never clean up a dead dashboard someone
imported by hand: that stays a manual job.

Two brakes. It refuses to run when the source lists fewer than half the dashboards
in the manifest, since a truncated `/api/search` would otherwise make everything
look deleted. And it aborts above `--max` matches, 50 by default. Every deleted
dashboard is saved to `out/prune_backup/` first, read from the target, because the
source copy is gone by definition.

Folders, library panels, playlists and annotations are not pruned.

## Library panels

A dashboard references a library panel by uid and renders `Unable to load library
panel: <uid>` when it is missing, so these go **before** the dashboards that use
them. `plan` flags affected dashboards in its `warnings` column.

```bash
./grafana_migrate.py library-panels           # reports only
./grafana_migrate.py library-panels --apply   # writes
```

The uid is preserved, so dashboards already on the target pick their panels up
without being re-imported. Re-run `apply` on those dashboards afterwards if you
want Grafana's "Connected dashboards" list to be right: that link is recorded when
a dashboard is saved, not when the panel is created.

The panel model goes through the same datasource rewriting as a dashboard, and an
element pointing at an unmapped datasource is reported as blocked and not written.

## Annotations, playlists, preferences

```bash
./grafana_migrate.py annotations            # reports only
./grafana_migrate.py annotations --apply
./grafana_migrate.py playlists --apply
```

Annotations posted by a service account are skipped: they are CI deployment
markers, written continuously, and repointing the pipeline at the target beats
copying its backlog. `--include-bots` copies them anyway.

The annotations endpoint caps a single response, so history is walked backwards in
30-day slices, `--months` deep (24 by default). Identity across instances is
`(dashboard uid, panel id, time, text)`, since annotation ids are instance-local,
which makes the copy idempotent. The target records the importing account as the
author: the API offers no way to attribute an annotation to someone else.

Playlists reference dashboards by uid, which the migration preserves, so they work
as soon as their dashboards are there.

Organisation preferences are **not** handled here. Manage them as code, for
example with the Terraform `grafana_organization_preferences` resource: two owners
for one setting would fight on every apply. They are not a `grafana.ini` setting
either, Grafana Cloud has no `grafana.ini`.

## Alerting

Alert rules reuse the same datasource map as the dashboards, but run through their
own commands: a dashboard is inert, an alert rule wakes up an on-call rotation.

```bash
./grafana_migrate.py alerts-contacts    # contact points first: everything routes to them by name
./grafana_migrate.py alerts-routing     # templates, mute timings, policy tree
./grafana_migrate.py alerts-plan        # read out/alerts/plan.csv
./grafana_migrate.py alerts-apply       # rules land paused
```

What `alerts-plan` does to a rule:

- Rewrites the datasource uid in both places a rule stores it, `data[].datasourceUid`
  and the copy inside `data[].model.datasource`. Missing the second one leaves the
  query pointing at the old instance.
- Leaves expression queries (`__expr__`, `-100`) alone.
- Repoints annotation links from the source host to the target. Dashboard uids are
  preserved, so `/d/<uid>/...` stays valid and only the host was wrong. Links to
  Confluence, GitLab or anything else are untouched.
- Keeps the rule uid, drops `id`, `orgID`, `updated` and `provenance`.
- Skips rules with a `provenance` set: they are managed by another pipeline and
  would become read-only in the target UI. Redeploy them from that pipeline instead.

**Every rule is pushed paused**, whatever its state on the source. Unpausing is a
separate, deliberate step, and it is the moment the old instance's copy becomes a
duplicate: disable it there at the same time or the team gets paged twice.

Rules are pushed a whole group at a time so the group's evaluation interval is set
in the same call. Intervals here range from 60s to 86400s; pushing rules one by one
would silently re-evaluate all of them at the target's default.

### Reruns, alert rules

`alerts-apply` records the source `updated` of every rule it pushed in
`out/alerts/state.json`, and the next `alerts-plan` skips what has not moved.

**The skip is decided per group, never per rule.** `alerts-apply` pushes a whole
rule group in one call and that call replaces the group's contents, so holding one
unchanged rule out of the payload would delete it from the target. A group is
skipped only when every rule in it is unchanged; edit one rule and its whole group
is pushed again, siblings included.

Rules carry no version counter, so the comparison is on the `updated` timestamp,
string against string. Any format drift reads as "changed" and costs a redundant
push, which is the harmless direction. Unlike dashboards, the rules list endpoint
returns `updated` directly, so nothing extra is fetched to decide.

### Contact points

`alerts-contacts` reads `/api/v1/provisioning/contact-points/export?decrypt=true`
on the source and posts the result to the target. The decrypted export is held in
memory and never written to disk: it carries live Slack webhooks and paging keys.

The source service account needs `alert.provisioning.secrets:read`. On Grafana
Open Source that permission comes with the **Admin** basic role, which is the only
way to get it: fine-grained role assignment is an Enterprise and Cloud feature, so
a Viewer or Editor account cannot be granted it on its own. Without the permission
the endpoint returns 403 and the command says which permission is missing.

The target service account needs `alert.provisioning:write` for the alerting
commands. The Editor role is enough for dashboards but not for this.

### Routing

`alerts-routing` pushes the templates, then the mute timings, then the policy tree,
in that order because the tree references the other two by name.

The tree is a single object with replace semantics: one call overwrites the
target's entire routing. Two guards make that safe to automate. Every contact point
the tree sends to, at any depth, must already exist on the target or the command
refuses to run. And the target's current tree is snapshotted to
`out/alerts/routing_backup.json` before anything is written, so `alerts-rollback`
can put it back. If the target had no tree at all, rollback resets it to the stock
one rather than leaving yours in place.

### Rolling back the alerting

`alerts-rollback` deletes the rule groups listed in `out/alerts/rollback.json` and
restores the routing snapshot. Folders created by `alerts-apply` are removed only
when they are still empty: by then the dashboard migration may have filled one, and
deleting a folder takes its dashboards with it.

## Out of scope

Permissions, snapshots, alert silences, users and teams are not migrated.
Dashboards provisioned from source control are skipped: they should be redeployed
from their own repository, not copied.

## Rollback

`apply` records every object it *created* in `out/rollback.json`. `rollback` deletes
them, dashboards first, then folders in reverse creation order. Dashboards that were
*updated* rather than created are not reverted: Grafana keeps their version history,
so restore those from the target's dashboard version list.
