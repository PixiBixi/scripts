#!/usr/bin/env -S uv --quiet run --active --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "requests>=2.32",
#   "typer>=0.15",
#   "rich>=13.9",
# ]
# ///
"""Migrate Grafana folders and dashboards from one instance to another.

Dry-run by default: `plan` never writes to the target. Only `apply` does.

Credentials come from the environment, never from flags:
    SRC_URL / SRC_TOKEN   source instance   (e.g. https://grafana.example.com)
    DST_URL / DST_TOKEN   target instance   (e.g. https://example.grafana.net)

The source falls back to GRAFANA_URL and GRAFANA_TOKEN (then
GRAFANA_SERVICE_ACCOUNT_TOKEN) when SRC_* are unset. DST_TOKEN is asked for
interactively when it is not set.
"""

from __future__ import annotations

import csv
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import unquote

import requests
import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

console = Console(stderr=True)
app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help=__doc__,
    rich_markup_mode="rich",
)

DEFAULT_OUT = Path("out")
SEARCH_PAGE_SIZE = 500
# Grafana Cloud rate-limits the HTTP API per org. The ceiling is not published and
# support can raise it, so the script self-throttles instead of assuming a number:
# writes stay sequential, and 429 is retried with backoff honouring Retry-After.
MAX_RETRIES = 6
DEFAULT_RPS = 10.0

# Built-in datasources exist on every instance under a fixed uid: never remap them.
BUILTIN_DS = frozenset(
    {
        "grafana",
        "-- grafana --",
        "-- mixed --",
        "-- dashboard --",
        "mixed",
        "dashboard",
        "-- expression --",
        "__expr__",
        "-100",
    }
)

# "$ds", "${ds}", "${ds:raw}" -- a reference to a template variable, not to a real uid.
VAR_RE = re.compile(r"^\$\{?[\w-]+(?::[\w-]+)?\}?$")

# Short links are rows in the old instance's database: no host swap revives them.
GOTO_RE = re.compile(r"/goto/[\w-]+")
# A template variable pinned in a link, e.g. "&var-datasource=4d9f3e30df7b".
VAR_PARAM_RE = re.compile(r"(?P<key>[?&]var-[\w.-]+=)(?P<value>[^&#\s\"'<>()\[\]]+)")


class Method(StrEnum):
    """How a source datasource was matched to a target one."""

    UID = "uid"
    NAME = "name"
    MANUAL = "manual"
    DROPPED = "DROPPED"
    UNRESOLVED = "UNRESOLVED"


# Sentinel written in the dst_uid column to declare a datasource deliberately
# abandoned: dashboards using it migrate untouched instead of being blocked.
DROP_SENTINEL = "DROP"


# --------------------------------------------------------------------------- #
# HTTP client
# --------------------------------------------------------------------------- #


class GrafanaError(RuntimeError):
    """A Grafana API call failed in a way the caller cannot recover from."""


class GrafanaClient:
    """Thin Grafana HTTP API client with retry/backoff on 429 and 5xx."""

    def __init__(self, base_url: str, token: str, label: str, rps: float = DEFAULT_RPS) -> None:
        """Build a client.

        Args:
            base_url: Root URL of the instance, with or without a trailing slash.
            token: Service account token, sent as a bearer token.
            label: Human-readable name used in errors and logs ("source"/"target").
            rps: Client-side ceiling on requests per second. 0 disables throttling.
        """
        self.base_url = base_url.rstrip("/")
        self.label = label
        self.min_interval = 1.0 / rps if rps > 0 else 0.0
        self._last_call = 0.0
        self.throttled_for = 0.0
        self.rate_limited = 0
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any | None = None,
        allow_404: bool = False,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Issue one API call, retrying on 429 and 5xx.

        Args:
            method: HTTP verb.
            path: API path starting with a slash.
            params: Query string parameters.
            json_body: Body serialised as JSON.
            allow_404: Return None instead of raising when the object is absent.
            headers: Extra headers merged into the session ones for this call.

        Returns:
            The decoded JSON body, or None on an allowed 404.

        Raises:
            GrafanaError: On a non-retryable error status or exhausted retries.
        """
        url = f"{self.base_url}{path}"
        delay = 1.0
        for attempt in range(1, MAX_RETRIES + 1):
            self._pace()
            try:
                resp = self.session.request(
                    method, url, params=params, json=json_body, timeout=60, headers=headers
                )
            except requests.RequestException as exc:
                if attempt == MAX_RETRIES:
                    raise GrafanaError(f"[{self.label}] {method} {path}: {exc}") from exc
                time.sleep(delay)
                delay *= 2
                continue

            if resp.status_code == 404 and allow_404:
                return None
            if resp.status_code == 429:
                self.rate_limited += 1
            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt == MAX_RETRIES:
                    raise GrafanaError(
                        f"[{self.label}] {method} {path}: HTTP {resp.status_code} "
                        f"after {MAX_RETRIES} attempts: {resp.text[:300]}"
                    )
                wait = float(resp.headers.get("Retry-After", delay))
                time.sleep(wait)
                delay *= 2
                continue
            if not resp.ok:
                raise GrafanaError(
                    f"[{self.label}] {method} {path}: HTTP {resp.status_code}: "
                    f"{resp.text[:500]}"
                )
            if not resp.content:
                return None
            return resp.json()
        raise GrafanaError(f"[{self.label}] {method} {path}: retries exhausted")

    def _pace(self) -> None:
        """Sleep just enough to stay under the configured requests-per-second."""
        if not self.min_interval:
            return
        wait = self._last_call + self.min_interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
            self.throttled_for += wait
        self._last_call = time.monotonic()

    def get(self, path: str, **kwargs: Any) -> Any:
        """GET a path."""
        return self.request("GET", path, **kwargs)

    def post(self, path: str, body: Any, **kwargs: Any) -> Any:
        """POST a JSON body to a path."""
        return self.request("POST", path, json_body=body, **kwargs)

    def put(self, path: str, body: Any, **kwargs: Any) -> Any:
        """PUT a JSON body to a path."""
        return self.request("PUT", path, json_body=body, **kwargs)

    @property
    def host(self) -> str:
        """The bare hostname, used to rewrite links that hardcode the instance."""
        return self.base_url.split("://", 1)[-1].split("/", 1)[0]

    def delete(self, path: str, **kwargs: Any) -> Any:
        """DELETE a path."""
        return self.request("DELETE", path, **kwargs)

    # -- domain helpers ---------------------------------------------------- #

    def whoami(self) -> str:
        """Return a short description of the authenticated principal."""
        info = self.get("/api/user", allow_404=True)
        if isinstance(info, dict) and info.get("login"):
            return str(info["login"])
        health = self.get("/api/health", allow_404=True) or {}
        return f"service account (grafana {health.get('version', '?')})"

    def list_datasources(self) -> list[dict[str, Any]]:
        """Return every datasource visible to the token."""
        return list(self.get("/api/datasources") or [])

    def search(self, kind: str) -> list[dict[str, Any]]:
        """Page through /api/search for one object type.

        Args:
            kind: Either "dash-db" or "dash-folder".

        Returns:
            Every matching search hit.
        """
        out: list[dict[str, Any]] = []
        page = 1
        while True:
            batch = self.get(
                "/api/search",
                params={"type": kind, "limit": SEARCH_PAGE_SIZE, "page": page},
            )
            if not batch:
                break
            out.extend(batch)
            if len(batch) < SEARCH_PAGE_SIZE:
                break
            page += 1
        return out

    def get_folder(self, uid: str) -> dict[str, Any] | None:
        """Fetch one folder, or None when it does not exist."""
        return self.get(f"/api/folders/{uid}", allow_404=True)

    def get_dashboard(self, uid: str) -> dict[str, Any] | None:
        """Fetch one dashboard envelope (dashboard + meta), or None when absent."""
        return self.get(f"/api/dashboards/uid/{uid}", allow_404=True)


# --------------------------------------------------------------------------- #
# Datasource mapping
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class MapRow:
    """One line of the source-to-target datasource correspondence table."""

    src_uid: str
    src_name: str
    src_type: str
    dst_uid: str
    dst_name: str
    dst_type: str
    method: str

    @property
    def resolved(self) -> bool:
        """True when this source datasource has a target counterpart."""
        return bool(self.dst_uid) and self.method not in (Method.UNRESOLVED, Method.DROPPED)

    @property
    def dropped(self) -> bool:
        """True when this datasource was declared abandoned by the operator."""
        return self.method == Method.DROPPED


MAP_FIELDS = ["src_uid", "src_name", "src_type", "dst_uid", "dst_name", "dst_type", "method"]


def build_datasource_map(
    src: list[dict[str, Any]], dst: list[dict[str, Any]]
) -> list[MapRow]:
    """Correlate source datasources with target ones.

    Matching is attempted by uid first (the case where the target was provisioned
    with identical uids), then by name+type, then by name alone. Anything left
    over is reported as UNRESOLVED rather than guessed: a wrong datasource is a
    silently empty dashboard, which is worse than a loud failure.

    Args:
        src: Datasource objects from the source instance.
        dst: Datasource objects from the target instance.

    Returns:
        One row per source datasource, sorted by name.
    """
    dst_by_uid = {d["uid"]: d for d in dst}
    dst_by_name_type: dict[tuple[str, str], dict[str, Any]] = {}
    dst_by_name: dict[str, dict[str, Any]] = {}
    for d in dst:
        dst_by_name_type.setdefault((d["name"].strip().lower(), d["type"]), d)
        dst_by_name.setdefault(d["name"].strip().lower(), d)

    rows: list[MapRow] = []
    for s in src:
        s_uid, s_name, s_type = s["uid"], s["name"], s["type"]
        match: dict[str, Any] | None = None
        method = Method.UNRESOLVED

        if s_uid in dst_by_uid:
            match, method = dst_by_uid[s_uid], Method.UID
        elif (s_name.strip().lower(), s_type) in dst_by_name_type:
            match, method = dst_by_name_type[(s_name.strip().lower(), s_type)], Method.NAME
        elif s_name.strip().lower() in dst_by_name:
            match, method = dst_by_name[s_name.strip().lower()], Method.NAME

        rows.append(
            MapRow(
                src_uid=s_uid,
                src_name=s_name,
                src_type=s_type,
                dst_uid=match["uid"] if match else "",
                dst_name=match["name"] if match else "",
                dst_type=match["type"] if match else "",
                method=str(method),
            )
        )
    return sorted(rows, key=lambda r: r.src_name.lower())


def write_map_csv(rows: list[MapRow], path: Path) -> None:
    """Write the correspondence table so it can be corrected by hand."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=MAP_FIELDS)
        writer.writeheader()
        for row in rows:
            out = {f: getattr(row, f) for f in MAP_FIELDS}
            if row.dropped:
                out["dst_uid"] = DROP_SENTINEL
            writer.writerow(out)


def read_map_csv(path: Path) -> list[MapRow]:
    """Read back a correspondence table, honouring hand edits.

    A row whose dst_uid was filled in by hand is marked MANUAL so the operator
    can tell it apart from an automatic match in the report.
    """
    rows: list[MapRow] = []
    with path.open(newline="", encoding="utf-8") as fh:
        for raw in csv.DictReader(fh):
            method = (raw.get("method") or "").strip()
            dst_uid = (raw.get("dst_uid") or "").strip()
            if dst_uid.upper() == DROP_SENTINEL:
                dst_uid, method = "", str(Method.DROPPED)
            elif dst_uid and method == Method.UNRESOLVED:
                method = str(Method.MANUAL)
            elif not dst_uid:
                method = str(Method.UNRESOLVED)
            rows.append(
                MapRow(
                    src_uid=(raw.get("src_uid") or "").strip(),
                    src_name=(raw.get("src_name") or "").strip(),
                    src_type=(raw.get("src_type") or "").strip(),
                    dst_uid=dst_uid,
                    dst_name=(raw.get("dst_name") or "").strip(),
                    dst_type=(raw.get("dst_type") or "").strip(),
                    method=method,
                )
            )
    return rows


class Resolver:
    """Resolves datasource references found in dashboard JSON."""

    def __init__(self, rows: list[MapRow]) -> None:
        """Build a resolver from the correspondence table."""
        self.by_uid = {r.src_uid: r for r in rows if r.src_uid}
        self.by_name = {r.src_name.strip().lower(): r for r in rows if r.src_name}

    def by_uid_or_name(self, value: str) -> MapRow | None:
        """Look a reference up by uid first, then by datasource name."""
        row = self.by_uid.get(value)
        if row is None:
            row = self.by_name.get(value.strip().lower())
        return row


# --------------------------------------------------------------------------- #
# Dashboard JSON rewriting
# --------------------------------------------------------------------------- #


@dataclass
class RewriteStats:
    """What a rewrite pass changed, and what it could not."""

    rewritten: int = 0
    already_correct: int = 0
    template_refs: int = 0
    builtin_refs: int = 0
    inherited_default: int = 0
    unresolved: list[str] = field(default_factory=list)
    dangling: list[str] = field(default_factory=list)
    dropped: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    blocking_uids: set[str] = field(default_factory=set)
    relinked: int = 0
    relinked_ds: int = 0
    goto_links: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when nothing blocks the migration of this dashboard.

        Dangling references do not block: they point at datasources that are
        already absent from the *source*, so the dashboard is broken today and
        copying it as-is introduces no regression. Only a datasource that exists
        on the source and has no target counterpart is a real blocker.
        """
        return not self.unresolved


def is_variable_ref(value: str) -> bool:
    """True when the string is a template-variable reference such as ``${ds}``."""
    return bool(VAR_RE.match(value.strip()))


def is_builtin_ref(value: str) -> bool:
    """True when the string names a built-in datasource present on every instance."""
    return value.strip().lower() in BUILTIN_DS


def _resolve_ref(value: str, resolver: Resolver, stats: RewriteStats, path: str) -> str:
    """Map one uid-or-name string to its target uid, recording why if it cannot."""
    if is_variable_ref(value):
        stats.template_refs += 1
        return value
    if is_builtin_ref(value):
        stats.builtin_refs += 1
        return value
    row = resolver.by_uid_or_name(value)
    if row is None:
        # Not a datasource of the source instance either: already broken upstream.
        stats.dangling.append(f"{path}: {value!r} does not exist on the source either")
        return value
    if row.dropped:
        # Declared abandoned: the reference stays as-is and the dashboard migrates.
        stats.dropped.append(f"{path}: {row.src_name!r} ({row.src_type}) dropped on purpose")
        return value
    if not row.resolved:
        stats.unresolved.append(
            f"{path}: {row.src_name!r} ({row.src_type}) has no target mapping"
        )
        stats.blocking_uids.add(row.src_uid)
        return value
    if row.dst_uid == value:
        stats.already_correct += 1
    else:
        stats.rewritten += 1
    return row.dst_uid


def _rewrite_ds_field(
    value: Any, resolver: Resolver, stats: RewriteStats, path: str
) -> Any:
    """Rewrite the value of a ``datasource`` key in any of its historical shapes."""
    if value is None:
        # Inherits whatever the target instance calls its default datasource.
        stats.inherited_default += 1
        return None
    if isinstance(value, str):
        return _resolve_ref(value, resolver, stats, path)
    if isinstance(value, dict):
        uid = value.get("uid")
        if not isinstance(uid, str):
            return value
        new = dict(value)
        new["uid"] = _resolve_ref(uid, resolver, stats, path)
        return new
    return value


def _walk(node: Any, resolver: Resolver, stats: RewriteStats, path: str) -> Any:
    """Recursively copy a JSON tree, rewriting every datasource reference in it."""
    if isinstance(node, dict):
        out: dict[str, Any] = {}
        for key, value in node.items():
            child = f"{path}.{key}" if path else key
            if key == "datasource":
                out[key] = _rewrite_ds_field(value, resolver, stats, child)
            elif key == "datasourceUid" and isinstance(value, str):
                out[key] = _resolve_ref(value, resolver, stats, child)
            else:
                out[key] = _walk(value, resolver, stats, child)
        if "libraryPanel" in node:
            title = node.get("title") or node.get("libraryPanel", {}).get("name") or "?"
            stats.warnings.append(
                f"{path}: panel {title!r} uses a library panel, which this run does not migrate"
            )
        if "alert" in node and isinstance(node.get("alert"), dict):
            stats.warnings.append(
                f"{path}: legacy panel alert present, not migrated"
            )
        return out
    if isinstance(node, list):
        return [_walk(v, resolver, stats, f"{path}[{i}]") for i, v in enumerate(node)]
    return node


def _rewrite_template_vars(
    dashboard: dict[str, Any], resolver: Resolver, stats: RewriteStats
) -> None:
    """Remap the selected value of ``datasource``-type template variables in place.

    These variables store the plugin type in ``query`` (unchanged across instances)
    but the *selected* datasource uid in ``current.value``, which does change. An
    unmappable selection is cleared rather than treated as a blocker: it is only
    the picker's last state, and the panels behind it reference ``${var}``.
    """
    for i, var in enumerate(dashboard.get("templating", {}).get("list", []) or []):
        if not isinstance(var, dict) or var.get("type") != "datasource":
            continue
        current = var.get("current")
        if not isinstance(current, dict):
            continue
        value = current.get("value")
        if not isinstance(value, str) or not value or is_variable_ref(value):
            continue
        path = f"templating.list[{i}].current.value"
        row = resolver.by_uid_or_name(value)
        if row is not None and row.resolved:
            if row.dst_uid == value:
                stats.already_correct += 1
            else:
                stats.rewritten += 1
            current["value"] = row.dst_uid
            continue
        # Grafana repopulates the picker from the variable's own query on load, so
        # a stale selection is cosmetic. Blocking a dashboard on it would be wrong:
        # its panels point at ${var}, not at this uid.
        stats.warnings.append(f"{path}: stale picker selection {value!r} cleared")
        current["value"] = ""
        current["text"] = ""


def _remap_var_param(match: re.Match[str], resolver: Resolver, stats: RewriteStats) -> str:
    """Repoint one ``var-<name>=<value>`` link parameter whose value is a source datasource uid.

    Only uids are looked up, never names: a value such as ``prod`` or ``All`` can
    collide with a datasource name and must not be rewritten.
    """
    raw = match.group("value")
    row = resolver.by_uid.get(unquote(raw))
    if row is None or not row.resolved or row.dst_uid == raw:
        return match.group(0)
    stats.relinked_ds += 1
    return f"{match.group('key')}{row.dst_uid}"


def relink_text(
    value: str, src_host: str, dst_host: str, resolver: Resolver, stats: RewriteStats, path: str
) -> str:
    """Repoint a string's links from the source instance to the target.

    Dashboard uids are preserved, so ``/d/<uid>/...`` only needs the host swapped.
    A datasource uid pinned in such a link (``var-datasource=<uid>``) is
    instance-local and is remapped like any other reference. ``/goto/`` short links
    cannot be fixed and are reported instead.

    Args:
        value: Any string of the dashboard: link URL, text panel, description.
        src_host: Hostname of the source instance.
        dst_host: Hostname of the target instance.
        resolver: Datasource correspondence table.
        stats: Collects what was changed and the short links left behind.
        path: JSON path of the string, for the report.

    Returns:
        The string with every source link repointed.
    """
    if not src_host or src_host not in value:
        return value
    # Whole hostname only: "grafana.example.com.evil.net" or "mygrafana.example.com" stay as they are.
    host = rf"(?<![\w.-]){re.escape(src_host)}(?![\w-]|\.[\w-])"
    url_re = re.compile(rf"https?://{host}[^\s\"'<>()\[\]]*")

    def relink_url(match: re.Match[str]) -> str:
        url = match.group(0)
        if GOTO_RE.search(url):
            stats.goto_links.append(f"{path}: {url}")
        return VAR_PARAM_RE.sub(lambda p: _remap_var_param(p, resolver, stats), url)

    relinked = url_re.sub(relink_url, value)
    relinked, count = re.subn(host, dst_host, relinked)
    stats.relinked += count
    return relinked


def relink_tree(
    node: Any, src_host: str, dst_host: str, resolver: Resolver, stats: RewriteStats, path: str = ""
) -> Any:
    """Recursively copy a JSON tree, repointing every string's source links."""
    if isinstance(node, dict):
        return {
            key: relink_tree(value, src_host, dst_host, resolver, stats, f"{path}.{key}" if path else key)
            for key, value in node.items()
        }
    if isinstance(node, list):
        return [
            relink_tree(v, src_host, dst_host, resolver, stats, f"{path}[{i}]")
            for i, v in enumerate(node)
        ]
    if isinstance(node, str):
        return relink_text(node, src_host, dst_host, resolver, stats, path)
    return node


def rewrite_dashboard(
    dashboard: dict[str, Any], resolver: Resolver, src_host: str = "", dst_host: str = ""
) -> tuple[dict[str, Any], RewriteStats]:
    """Return a target-ready copy of a dashboard plus a report on the rewrite.

    The dashboard uid is preserved so reruns are idempotent and existing
    permalinks keep working. The numeric id is dropped because it is instance-local.

    Args:
        dashboard: The ``dashboard`` object as returned by the source API.
        resolver: Datasource correspondence table.
        src_host: Hostname of the source instance. Empty skips the link rewrite.
        dst_host: Hostname of the target instance.

    Returns:
        The rewritten dashboard and the statistics collected while rewriting.
    """
    stats = RewriteStats()
    out = _walk(dashboard, resolver, stats, "")
    _rewrite_template_vars(out, resolver, stats)
    out = relink_tree(out, src_host, dst_host, resolver, stats)
    out["id"] = None
    out.pop("version", None)
    return out, stats


# --------------------------------------------------------------------------- #
# Folders
# --------------------------------------------------------------------------- #


@dataclass
class Folder:
    """A source folder and its place in the folder tree."""

    uid: str
    title: str
    parent_uid: str | None


def fetch_folders(client: GrafanaClient) -> dict[str, Folder]:
    """Fetch every folder with its parent, keyed by uid.

    ``/api/search`` returns the folder tree flat; the parent link only comes back
    from ``/api/folders/:uid``, so each folder needs its own call.
    """
    folders: dict[str, Folder] = {}
    hits = client.search("dash-folder")
    for hit in hits:
        uid = hit["uid"]
        detail = client.get_folder(uid) or {}
        folders[uid] = Folder(
            uid=uid,
            title=detail.get("title") or hit.get("title") or uid,
            parent_uid=detail.get("parentUid") or None,
        )
    return folders


def order_folders(folders: dict[str, Folder]) -> list[Folder]:
    """Sort folders so that every parent precedes its children.

    Args:
        folders: Folders keyed by uid.

    Returns:
        Folders in an order safe to create sequentially. Folders whose parent is
        missing from the set are treated as roots.

    Raises:
        GrafanaError: When the parent links contain a cycle.
    """
    ordered: list[Folder] = []
    placed: set[str] = set()
    remaining = dict(folders)
    while remaining:
        progressed = False
        for uid, folder in list(remaining.items()):
            parent = folder.parent_uid
            if parent is None or parent in placed or parent not in folders:
                ordered.append(folder)
                placed.add(uid)
                del remaining[uid]
                progressed = True
        if not progressed:
            raise GrafanaError(
                f"cycle in folder hierarchy: {', '.join(sorted(remaining))}"
            )
    return ordered



# --------------------------------------------------------------------------- #
# Alert rules
# --------------------------------------------------------------------------- #

# Instance-local or server-owned fields that must not be carried over.
RULE_STRIP = ("id", "orgID", "updated", "provenance")

# Keeps rules editable in the target UI. Without it Grafana marks anything created
# through the provisioning API as provisioned, hence read-only for everyone.
NO_PROVENANCE = {"X-Disable-Provenance": "true"}

URL_RE = re.compile(r"https?://([\w.-]+)")


@dataclass
class RuleGroup:
    """A folder + group pair and the evaluation interval it runs at."""

    folder_uid: str
    name: str
    interval: int


def rewrite_annotation_links(rule: dict[str, Any], src_host: str, dst_host: str) -> int:
    """Repoint annotation links from the source instance to the target, in place.

    Dashboard uids are preserved by the dashboard migration, so ``/d/<uid>/...``
    stays valid and only the host is wrong. Links to anything else (Confluence,
    GitLab, Thanos) are left alone.

    Args:
        rule: The rule being rewritten.
        src_host: Hostname of the source instance.
        dst_host: Hostname of the target instance.

    Returns:
        How many annotation values were changed.
    """
    annotations = rule.get("annotations")
    if not isinstance(annotations, dict):
        return 0
    changed = 0
    for key, value in annotations.items():
        if not isinstance(value, str) or src_host not in value:
            continue
        annotations[key] = value.replace(src_host, dst_host)
        changed += 1
    return changed


def rewrite_alert_rule(
    rule: dict[str, Any], resolver: Resolver, src_host: str, dst_host: str
) -> tuple[dict[str, Any], RewriteStats, int]:
    """Return a target-ready copy of an alert rule.

    The rule uid is preserved so reruns are idempotent. The rule is forced to
    paused: a migrated alert must never start paging on its own, the operator
    unpauses per team once the routing is verified.

    Args:
        rule: A rule as returned by the provisioning API.
        resolver: Datasource correspondence table.
        src_host: Hostname of the source instance.
        dst_host: Hostname of the target instance.

    Returns:
        The rewritten rule, the rewrite statistics, and the number of relinked
        annotations.
    """
    stats = RewriteStats()
    out = _walk(rule, resolver, stats, "")
    for key in RULE_STRIP:
        out.pop(key, None)
    relinked = rewrite_annotation_links(out, src_host, dst_host)
    out["isPaused"] = True
    return out, stats, relinked


def fetch_rule_groups(
    client: GrafanaClient, rules: list[dict[str, Any]]
) -> dict[tuple[str, str], RuleGroup]:
    """Fetch the evaluation interval of every group the rules belong to.

    The interval lives on the group, not on the rule, so pushing rules without it
    would silently re-evaluate every alert at the target's default frequency.
    """
    groups: dict[tuple[str, str], RuleGroup] = {}
    for rule in rules:
        key = (rule.get("folderUID") or "", rule.get("ruleGroup") or "")
        if key in groups or not all(key):
            continue
        detail = client.get(
            f"/api/v1/provisioning/folder/{key[0]}/rule-groups/{key[1]}", allow_404=True
        )
        groups[key] = RuleGroup(key[0], key[1], int((detail or {}).get("interval") or 60))
    return groups


def rule_is_unchanged(state: dict[str, dict[str, Any]], rule: dict[str, Any]) -> bool:
    """True when a rule is at the exact timestamp the last apply pushed.

    Rules carry no version counter, so the comparison is on ``updated``, string
    against string. Equality can only under-report a change if Grafana reuses a
    timestamp across an edit, which it does not; any format drift shows up as a
    difference and costs a redundant push, which is the harmless direction.
    """
    known = state.get(rule.get("uid") or "")
    updated = rule.get("updated")
    if not isinstance(known, dict) or not updated:
        return False
    return known.get("updated") == updated


def unchanged_rule_groups(
    rules: list[dict[str, Any]], state: dict[str, dict[str, Any]]
) -> set[tuple[str, str]]:
    """Return the rule groups where every single rule is unchanged.

    The skip has to be decided per group, never per rule: apply pushes a whole
    group in one call and that call replaces the group's contents. Leaving one
    unchanged rule out of the payload would delete it from the target.
    """
    members: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for rule in rules:
        members[(rule.get("folderUID") or "", rule.get("ruleGroup") or "")].append(rule)
    return {
        key
        for key, group in members.items()
        if group and all(rule_is_unchanged(state, r) for r in group)
    }


def receiver_of(rule: dict[str, Any]) -> str | None:
    """Return the contact point a rule routes to directly, if it uses one."""
    settings = rule.get("notification_settings")
    if isinstance(settings, dict):
        name = settings.get("receiver")
        if isinstance(name, str) and name:
            return name
    return None

# --------------------------------------------------------------------------- #
# Shared plumbing
# --------------------------------------------------------------------------- #


# The source falls back to the ambient GRAFANA_* variables, which already point at
# the instance being migrated away from. The target has no fallback on purpose:
# nothing ambient should ever be able to become a write target by accident.
SRC_URL_VARS = ("SRC_URL", "GRAFANA_URL")
SRC_TOKEN_VARS = ("SRC_TOKEN", "GRAFANA_TOKEN", "GRAFANA_SERVICE_ACCOUNT_TOKEN")
DST_URL_VARS = ("DST_URL",)
DST_TOKEN_VARS = ("DST_TOKEN",)




def resolve_env(names: tuple[str, ...]) -> tuple[str, str] | None:
    """Return the first environment variable in ``names`` that holds a value.

    Args:
        names: Variable names in order of precedence.

    Returns:
        The winning ``(name, value)`` pair, or None when none of them is set.
    """
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return name, value
    return None


def resolve_target() -> tuple[str, str]:
    """Resolve the target URL and token, asking for the token when it is not set.

    The URL always comes from DST_URL, never from a default or an ambient
    variable: the write target must be stated explicitly. The token is read from
    DST_TOKEN or typed in, with the input hidden so it does not end up in the
    scrollback or the shell history.

    Returns:
        The target ``(url, token)``.

    Raises:
        typer.Exit: When DST_URL is unset, or no token is set and there is no
            terminal to ask on.
    """
    url_hit = resolve_env(DST_URL_VARS)
    if url_hit is None:
        console.print("[red]DST_URL is not set.[/red] The write target is never guessed.")
        console.print("  export DST_URL=https://<stack>.grafana.net")
        raise typer.Exit(2)
    url = url_hit[1]
    console.print(f"[dim]target {url}[/dim]")

    token_hit = resolve_env(DST_TOKEN_VARS)
    if token_hit:
        return url, token_hit[1]

    if not sys.stdin.isatty():
        console.print("[red]DST_TOKEN is not set and there is no terminal to ask on.[/red]")
        console.print(f"  export DST_TOKEN=glsa_...   # service account token on {url}")
        raise typer.Exit(2)

    token = typer.prompt(
        f"Service account token for {url}", hide_input=True, err=True
    ).strip()
    if not token:
        console.print("[red]Empty token.[/red]")
        raise typer.Exit(2)
    return url, token


def make_clients() -> tuple[GrafanaClient, GrafanaClient]:
    """Build the source and target clients from the environment.

    Raises:
        typer.Exit: When the source or the target cannot be resolved.
    """
    src_url_hit = resolve_env(SRC_URL_VARS)
    src_token_hit = resolve_env(SRC_TOKEN_VARS)
    if src_url_hit is None or src_token_hit is None:
        console.print("[red]Cannot resolve the source instance.[/red]")
        console.print("\n  export SRC_URL=https://grafana.example.com   # or GRAFANA_URL")
        console.print("  export SRC_TOKEN=...   # or GRAFANA_TOKEN, GRAFANA_SERVICE_ACCOUNT_TOKEN")
        raise typer.Exit(2)

    src_url_var, src_url = src_url_hit
    src_token_var, src_token = src_token_hit
    # Say which variable won: a forgotten ambient GRAFANA_URL must not silently
    # decide what gets read and copied.
    if src_url_var != "SRC_URL" or src_token_var != "SRC_TOKEN":
        console.print(
            f"[dim]source {src_url} (from ${src_url_var}, token from ${src_token_var})[/dim]"
        )

    dst_url, dst_token = resolve_target()
    rps = float(os.environ.get("GRAFANA_RPS", DEFAULT_RPS))
    return (
        GrafanaClient(src_url, src_token, "source", rps),
        GrafanaClient(dst_url, dst_token, "target", rps),
    )


def load_or_build_map(
    src: GrafanaClient, dst: GrafanaClient, out_dir: Path, rebuild: bool = False
) -> list[MapRow]:
    """Return the datasource correspondence table, from disk when it exists."""
    path = out_dir / "datasource_map.csv"
    if path.exists() and not rebuild:
        console.print(f"Using datasource map [cyan]{path}[/cyan]")
        return read_map_csv(path)
    rows = build_datasource_map(src.list_datasources(), dst.list_datasources())
    write_map_csv(rows, path)
    console.print(f"Wrote datasource map [cyan]{path}[/cyan]")
    return rows


def selected_dashboards(
    src: GrafanaClient,
    folders: dict[str, Folder],
    folder_filters: list[str],
    exclude: list[str],
    include_backups: bool,
    limit: int | None,
) -> list[dict[str, Any]]:
    """Return the search hits for the dashboards this run should migrate."""
    hits = src.search("dash-db")
    excl = [re.compile(p) for p in exclude]
    if not include_backups:
        excl.append(re.compile(r"^Backups$"))
    keep: list[dict[str, Any]] = []
    for hit in hits:
        folder_title = hit.get("folderTitle") or "General"
        if folder_filters and folder_title not in folder_filters:
            continue
        if any(p.search(folder_title) for p in excl):
            continue
        if any(p.search(hit.get("title", "")) for p in excl):
            continue
        keep.append(hit)
    keep.sort(key=lambda h: (h.get("folderTitle") or "", h.get("title") or ""))
    return keep[:limit] if limit else keep


def _safe(name: str) -> str:
    """Make a string safe to use as a path component."""
    return re.sub(r"[^\w.-]+", "_", name).strip("_") or "unnamed"


def load_state(path: Path) -> dict[str, dict[str, Any]]:
    """Read what the last successful apply pushed, keyed by dashboard uid.

    Returns an empty mapping when the file is missing or unreadable: a lost state
    file must cost a redundant push, never a crash.
    """
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def duplicate_of(twin: str | None, uid: str, exists_on_target: bool) -> str:
    """Return the uid of the target dashboard this push would sit beside, if any.

    Only a create can produce a twin. When the uid is already on the target the
    push overwrites it in place, even if a homonym sits in the same folder: that
    is a pair copied from the source, and skipping it would leave the dashboard
    frozen at its previous version.
    """
    if exists_on_target or not twin or twin == uid:
        return ""
    return twin


def is_unchanged(state: dict[str, dict[str, Any]], uid: str, version: Any) -> bool:
    """True when this dashboard is at the exact version the last apply pushed.

    Grafana bumps ``version`` on every save, so equality means the source has not
    been touched since. It says nothing about the target: an edit made directly on
    the target is invisible here, which is what ``--force`` is for.
    """
    known = state.get(uid)
    if not isinstance(known, dict) or version is None:
        return False
    return known.get("version") == version


def index_by_folder_title(hits: list[dict[str, Any]]) -> dict[tuple[str, str], str]:
    """Index dashboards by (folder title, dashboard title), lowercased, to their uid.

    Used to spot a dashboard already sitting on the target under a different uid,
    which a uid-only existence check cannot see.
    """
    index: dict[tuple[str, str], str] = {}
    for hit in hits:
        folder = (hit.get("folderTitle") or "General").strip().lower()
        title = (hit.get("title") or "").strip().lower()
        index.setdefault((folder, title), hit.get("uid", ""))
    return index


def is_empty_after_drop(stats: RewriteStats) -> bool:
    """True when every datasource a dashboard reads was declared abandoned.

    Such a dashboard still imports cleanly, it just renders nothing: there is no
    panel left with a live query behind it.
    """
    return bool(stats.dropped) and not (
        stats.rewritten or stats.already_correct or stats.template_refs
    )


def _skip(hit: dict[str, Any], uid: str, reason: str) -> dict[str, Any]:
    """Build a plan row for a dashboard this run deliberately leaves alone."""
    return {
        "uid": uid,
        "title": hit.get("title", ""),
        "folder": hit.get("folderTitle", ""),
        "action": "skip",
        "reason": reason,
    }


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #

OutDir = Annotated[Path, typer.Option("--out", help="Directory for reports and payloads.")]
FolderOpt = Annotated[
    list[str] | None, typer.Option("--folder", help="Only this folder title. Repeatable.")
]
ExcludeOpt = Annotated[
    list[str] | None,
    typer.Option("--exclude", help="Regex on folder or dashboard title. Repeatable."),
]
BackupsOpt = Annotated[bool, typer.Option("--include-backups", help="Do not skip the Backups folder.")]
LimitOpt = Annotated[int, typer.Option("--limit", help="Stop after N dashboards. 0 means no limit.")]


@app.command()
def preflight(
    out: OutDir = DEFAULT_OUT,
    rebuild: Annotated[
        bool, typer.Option("--rebuild", help="Discard an existing map and rebuild it.")
    ] = False,
) -> None:
    """Check both instances and build the datasource correspondence table."""
    src, dst = make_clients()
    for client in (src, dst):
        console.print(f"[green]OK[/green] {client.label}: {client.base_url} as {client.whoami()}")

    src_ds, dst_ds = src.list_datasources(), dst.list_datasources()
    console.print(f"source datasources: {len(src_ds)}   target datasources: {len(dst_ds)}")

    map_path = out / "datasource_map.csv"
    if rebuild or not map_path.exists():
        rows = build_datasource_map(src_ds, dst_ds)
        write_map_csv(rows, map_path)
    else:
        rows = read_map_csv(map_path)

    counts = Counter(r.method for r in rows)
    table = Table(title="Datasource matching", show_lines=False)
    table.add_column("method")
    table.add_column("count", justify="right")
    for method, count in counts.most_common():
        style = "red" if method == Method.UNRESOLVED else "green"
        table.add_row(f"[{style}]{method}[/{style}]", str(count))
    console.print(table)

    unresolved = [r for r in rows if not r.resolved]
    if unresolved:
        miss = Table(title=f"{len(unresolved)} unresolved datasources", show_lines=False)
        for column in ("name", "type", "src uid"):
            miss.add_column(column)
        for row in unresolved[:40]:
            miss.add_row(row.src_name, row.src_type, row.src_uid)
        console.print(miss)
        console.print(
            f"Fill in [cyan]dst_uid[/cyan] for these rows in [cyan]{map_path}[/cyan], "
            "then rerun. Dashboards referencing them would render empty."
        )
    console.print(f"\n[green]preflight done[/green] -> {map_path}")


@app.command()
def plan(
    out: OutDir = DEFAULT_OUT,
    folder: FolderOpt = None,
    exclude: ExcludeOpt = None,
    include_backups: BackupsOpt = False,
    limit: LimitOpt = 0,
    skip_empty: Annotated[
        bool,
        typer.Option(
            "--skip-empty",
            help="Skip dashboards whose every datasource was dropped: they would render nothing.",
        ),
    ] = False,
    force: Annotated[
        bool,
        typer.Option("--force", help="Replan everything, ignoring what the last apply pushed."),
    ] = False,
) -> None:
    """Build every target payload on disk without writing anything to the target."""
    src, dst = make_clients()
    rows = load_or_build_map(src, dst, out)
    resolver = Resolver(rows)

    folders = fetch_folders(src)
    hits = selected_dashboards(
        src, folders, folder or [], exclude or [], include_backups, limit or None
    )
    console.print(f"{len(hits)} dashboards selected, {len(folders)} folders on source")

    # An earlier hand-made import may sit on the target under a different uid. Pushing
    # ours would then leave two dashboards with the same name in the same folder.
    target_index = index_by_folder_title(dst.search("dash-db"))

    payload_dir = out / "dashboards"
    report: list[dict[str, Any]] = []
    blocking = 0
    dangling_dashboards = 0
    empty_dashboards: list[str] = []
    duplicates: list[dict[str, str]] = []
    state = {} if force else load_state(out / "state.json")
    if state:
        console.print(f"{len(state)} dashboards already pushed, from {out / 'state.json'}")
    blockers: Counter[str] = Counter()

    with Progress(
        SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("planning", total=len(hits))
        for hit in hits:
            uid = hit["uid"]
            progress.update(task, description=f"planning {hit.get('title', uid)[:48]}")
            envelope = src.get_dashboard(uid)
            if envelope is None:
                report.append(_skip(hit, uid, "vanished from source"))
                progress.advance(task)
                continue
            meta = envelope.get("meta", {})
            src_version = meta.get("version")
            if is_unchanged(state, uid, src_version):
                report.append(
                    _skip(hit, uid, f"unchanged since last apply (version {src_version})")
                )
                progress.advance(task)
                continue
            if meta.get("provisioned"):
                report.append(_skip(hit, uid, "provisioned from source control"))
                progress.advance(task)
                continue

            dashboard, stats = rewrite_dashboard(envelope["dashboard"], resolver, src.host, dst.host)
            if stats.dangling:
                dangling_dashboards += 1
            if is_empty_after_drop(stats):
                empty_dashboards.append(f"{hit.get('folderTitle') or 'General'}/{hit.get('title')}")
                if skip_empty:
                    report.append(
                        _skip(hit, uid, "every datasource dropped: would arrive empty")
                    )
                    progress.advance(task)
                    continue
            folder_title = hit.get("folderTitle") or "General"
            folder_uid = hit.get("folderUid") or ""
            exists = dst.get_dashboard(uid) is not None
            action = "update" if exists else "create"
            twin = target_index.get(
                ((folder_title or "General").strip().lower(), (hit.get("title") or "").strip().lower())
            )
            duplicate_uid = duplicate_of(twin, uid, exists)
            if duplicate_uid:
                duplicates.append(
                    {"folder": folder_title, "title": hit.get("title", ""),
                     "source_uid": uid, "target_uid": duplicate_uid}
                )
                action = "DUPLICATE"
            if not stats.ok:
                action = "BLOCKED"
                blocking += 1
                blockers.update(stats.blocking_uids)

            target = payload_dir / _safe(folder_title) / f"{_safe(hit.get('title', uid))}.{uid}.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                json.dumps(
                    {
                        "dashboard": dashboard,
                        "folderUid": folder_uid,
                        "overwrite": True,
                        "message": f"migrated from {src.base_url}",
                    },
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            report.append(
                {
                    "uid": uid,
                    "title": hit.get("title", ""),
                    "folder": folder_title,
                    "action": action,
                    "rewritten": stats.rewritten,
                    "already_correct": stats.already_correct,
                    "template_refs": stats.template_refs,
                    "builtin_refs": stats.builtin_refs,
                    "inherited_default": stats.inherited_default,
                    "unresolved": " | ".join(stats.unresolved),
                    "dangling": " | ".join(stats.dangling),
                    "dropped": " | ".join(stats.dropped),
                    "duplicate_uid": duplicate_uid,
                    "relinked": stats.relinked,
                    "relinked_ds": stats.relinked_ds,
                    "goto_links": " | ".join(stats.goto_links),
                    "src_version": src_version,
                    "src_updated": meta.get("updated", ""),
                    "warnings": " | ".join(stats.warnings),
                    "payload": str(target),
                }
            )
            progress.advance(task)

    report_path = out / "plan.csv"
    fields = [
        "uid", "title", "folder", "action", "reason",
        "rewritten", "already_correct", "template_refs", "builtin_refs", "inherited_default",
        "unresolved", "dangling", "dropped", "duplicate_uid",
        "relinked", "relinked_ds", "goto_links",
        "src_version", "src_updated", "warnings", "payload",
    ]
    with report_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(report)

    # One missing datasource blocks many dashboards, so the actionable list is the
    # datasources, not the dashboards.
    by_uid = {r.src_uid: r for r in rows}
    blockers_path = out / "blockers.csv"
    with blockers_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["dashboards_blocked", "src_name", "src_type", "src_uid"])
        for uid, count in blockers.most_common():
            row = by_uid.get(uid)
            writer.writerow([count, row.src_name if row else "", row.src_type if row else "", uid])

    actions = Counter(r["action"] for r in report)
    summary = Table(title="Plan")
    summary.add_column("action")
    summary.add_column("count", justify="right")
    for action, count in actions.most_common():
        summary.add_row(action, str(count))
    console.print(summary)
    console.print(f"payloads -> [cyan]{payload_dir}[/cyan]\nreport   -> [cyan]{report_path}[/cyan]")
    if duplicates:
        dup_path = out / "duplicates.csv"
        with dup_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=["folder", "title", "source_uid", "target_uid"])
            writer.writeheader()
            writer.writerows(duplicates)
        console.print(
            f"[red]{len(duplicates)} dashboards already exist on the target under a different "
            f"uid.[/red] Pushing them would create a twin in the same folder, so they are marked "
            f"DUPLICATE and apply will refuse them."
        )
        console.print(
            f"Delete the target copies (earlier hand-made imports, or leftovers pruned from "
            f"the source) and rerun plan, "
            f"or pass --skip-duplicates. -> [cyan]{dup_path}[/cyan]"
        )
    if empty_dashboards:
        empty_path = out / "empty_after_drop.csv"
        empty_path.write_text(
            "dashboard\n" + "\n".join(empty_dashboards) + "\n", encoding="utf-8"
        )
        verb = "were skipped" if skip_empty else "will arrive empty"
        console.print(
            f"[yellow]{len(empty_dashboards)} dashboards depend only on dropped "
            f"datasources and {verb}.[/yellow] -> [cyan]{empty_path}[/cyan]"
        )
        if not skip_empty:
            console.print("Pass [bold]--skip-empty[/bold] to leave them behind instead.")
    if dangling_dashboards:
        console.print(
            f"[yellow]{dangling_dashboards} dashboards reference datasources that no longer "
            "exist on the source either.[/yellow] They are already broken today and are "
            "migrated as-is; see the dangling column to clean them up."
        )
    if blocking:
        console.print(
            f"[red]{blocking} dashboards blocked by {len(blockers)} missing datasources.[/red] "
            "apply will refuse them unless --skip-blocked."
        )
        top = Table(title="Datasources to create on the target, most blocking first")
        top.add_column("dashboards", justify="right")
        top.add_column("datasource")
        top.add_column("type")
        for uid, count in blockers.most_common(15):
            row = by_uid.get(uid)
            top.add_row(str(count), row.src_name if row else uid, row.src_type if row else "?")
        console.print(top)
        console.print(f"full list -> [cyan]{blockers_path}[/cyan]")


@app.command()
def apply(
    out: OutDir = DEFAULT_OUT,
    folder: FolderOpt = None,
    exclude: ExcludeOpt = None,
    include_backups: BackupsOpt = False,
    limit: LimitOpt = 0,
    skip_blocked: Annotated[
        bool,
        typer.Option(
            "--skip-blocked",
            help="Migrate resolvable dashboards and skip the rest instead of aborting.",
        ),
    ] = False,
    skip_duplicates: Annotated[
        bool,
        typer.Option(
            "--skip-duplicates",
            help="Leave dashboards that already exist on the target under another uid alone.",
        ),
    ] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Do not ask for confirmation.")] = False,
) -> None:
    """Create the folders and push the dashboards to the target instance."""
    src, dst = make_clients()
    plan_path = out / "plan.csv"
    if not plan_path.exists():
        console.print(f"[red]No plan found at {plan_path}.[/red] Run `plan` first and read it.")
        raise typer.Exit(2)

    with plan_path.open(newline="", encoding="utf-8") as fh:
        planned = list(csv.DictReader(fh))
    blocked = [r for r in planned if r["action"] == "BLOCKED"]
    dupes = [r for r in planned if r["action"] == "DUPLICATE"]
    todo = [r for r in planned if r["action"] in {"create", "update"}]
    if dupes and skip_duplicates:
        console.print(f"[yellow]{len(dupes)} duplicates skipped.[/yellow]")
    elif dupes:
        console.print(
            f"[red]{len(dupes)} dashboards already exist on the target under a different uid.[/red]"
        )
        console.print(
            f"See {out / 'duplicates.csv'}. Delete those target copies and rerun plan, "
            "or pass --skip-duplicates to leave them alone."
        )
        raise typer.Exit(1)

    if blocked and not skip_blocked:
        console.print(f"[red]{len(blocked)} dashboards have unresolved datasources.[/red]")
        console.print(f"Fix {out / 'datasource_map.csv'} and rerun `plan`, or pass --skip-blocked.")
        raise typer.Exit(1)

    console.print(f"Target: [bold]{dst.base_url}[/bold]")
    creates = sum(1 for r in todo if r["action"] == "create")
    console.print(
        f"{len(todo)} dashboards to write ({creates} create, {len(todo) - creates} update)"
    )
    if blocked:
        console.print(f"[yellow]{len(blocked)} blocked dashboards will be skipped.[/yellow]")
    if not yes and not typer.confirm("Write to the target instance?"):
        raise typer.Exit(1)

    created_folders: list[str] = []
    created_dashboards: list[str] = []

    folders = fetch_folders(src)
    wanted = {r["folder"] for r in todo} - {"General", ""}
    needed = {uid: f for uid, f in folders.items() if f.title in wanted}
    # Parents may fall outside the selection; pull them in so children can attach.
    frontier = list(needed.values())
    while frontier:
        current = frontier.pop()
        parent = current.parent_uid
        if parent and parent in folders and parent not in needed:
            needed[parent] = folders[parent]
            frontier.append(folders[parent])

    for f in order_folders(needed):
        if dst.get_folder(f.uid) is not None:
            continue
        body: dict[str, Any] = {"uid": f.uid, "title": f.title}
        if f.parent_uid:
            body["parentUid"] = f.parent_uid
        dst.post("/api/folders", body)
        created_folders.append(f.uid)
        console.print(f"  folder created: {f.title}")

    failures: list[tuple[str, str]] = []
    state_path = out / "state.json"
    state = load_state(state_path)
    with Progress(
        SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("applying", total=len(todo))
        for row in todo:
            progress.update(task, description=f"applying {row['title'][:48]}")
            payload = json.loads(Path(row["payload"]).read_text(encoding="utf-8"))
            try:
                dst.post("/api/dashboards/db", payload)
                if row["action"] == "create":
                    created_dashboards.append(row["uid"])
                # Recorded only on success, so a failed push is retried next run.
                if row.get("src_version"):
                    state[row["uid"]] = {
                        "version": int(row["src_version"]),
                        "updated": row.get("src_updated", ""),
                        "title": row.get("title", ""),
                    }
            except GrafanaError as exc:
                failures.append((row["uid"], str(exc)))
            progress.advance(task)
    state_path.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")

    rollback_path = out / "rollback.json"
    rollback_path.write_text(
        json.dumps({"dashboards": created_dashboards, "folders": created_folders}, indent=2),
        encoding="utf-8",
    )

    console.print(
        f"\n[green]{len(todo) - len(failures)} dashboards written[/green], "
        f"{len(created_folders)} folders created"
    )
    if dst.rate_limited or dst.throttled_for:
        console.print(
            f"rate limiting: {dst.rate_limited} HTTP 429 retried, "
            f"{dst.throttled_for:.0f}s spent self-throttling"
        )
    console.print(f"rollback manifest -> [cyan]{rollback_path}[/cyan]")
    console.print(f"{len(state)} dashboards recorded in [cyan]{state_path}[/cyan]")
    if failures:
        console.print(f"[red]{len(failures)} failures:[/red]")
        for uid, err in failures[:20]:
            console.print(f"  {uid}: {err}")
        raise typer.Exit(1)


def stored_schema(client: GrafanaClient, namespace: str, uid: str) -> str:
    """Return the schema version a dashboard is stored in (``v0alpha1``, ``v2``...).

    ``/api/dashboards`` serves every dashboard as v1, converting v2 ones on the fly,
    and saving through it would store them back as v1.

    Raises:
        GrafanaError: When the namespace is wrong or the API is unavailable.
    """
    body = client.get(f"/apis/dashboard.grafana.app/v1beta1/namespaces/{namespace}/dashboards/{uid}")
    return str(((body or {}).get("status") or {}).get("conversion", {}).get("storedVersion") or "")


@app.command()
def relink(
    out: OutDir = DEFAULT_OUT,
    src_host: Annotated[
        str,
        typer.Option("--src-host", help="Hostname of the old instance. Defaults to the host of $SRC_URL."),
    ] = "",
    namespace: Annotated[
        str,
        typer.Option(
            "--namespace", envvar="DST_NAMESPACE",
            help="Target API namespace: `default` on-prem, `stacks-<stack id>` on Grafana Cloud.",
        ),
    ] = "default",
    folder: FolderOpt = None,
    limit: LimitOpt = 0,
    apply_changes: Annotated[
        bool, typer.Option("--apply", help="Save the relinked dashboards. Without it this only reports.")
    ] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Do not ask for confirmation.")] = False,
) -> None:
    """Repoint links to the old instance in dashboards already on the target.

    Works on the target copy, so edits made there since the migration are kept.
    Only reads the source hostname, never the source API.
    """
    if not src_host:
        hit = resolve_env(SRC_URL_VARS)
        src_host = hit[1].split("://", 1)[-1].split("/", 1)[0] if hit else ""
    if not src_host:
        console.print("[red]Pass --src-host or set SRC_URL.[/red]")
        raise typer.Exit(2)
    map_path = out / "datasource_map.csv"
    if not map_path.exists():
        console.print(f"[red]No datasource map at {map_path}.[/red] Run `preflight` first.")
        raise typer.Exit(2)
    resolver = Resolver(read_map_csv(map_path))
    dst_url, dst_token = resolve_target()
    dst = GrafanaClient(dst_url, dst_token, "target", float(os.environ.get("GRAFANA_RPS", DEFAULT_RPS)))

    hits = [
        h for h in dst.search("dash-db")
        if not folder or (h.get("folderTitle") or "General") in folder
    ]
    hits = hits[:limit] if limit else hits
    console.print(f"{len(hits)} target dashboards, repointing {src_host} -> {dst.host}")

    payload_dir = out / "relink"
    payload_dir.mkdir(parents=True, exist_ok=True)
    report: list[dict[str, Any]] = []
    with Progress(
        SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("scanning", total=len(hits))
        for hit in hits:
            uid = hit["uid"]
            progress.update(task, description=f"scanning {hit.get('title', uid)[:48]}")
            progress.advance(task)
            envelope = dst.get_dashboard(uid)
            if envelope is None:
                continue
            stats = RewriteStats()
            dashboard = relink_tree(envelope["dashboard"], src_host, dst.host, resolver, stats)
            if not stats.relinked:
                continue
            meta = envelope.get("meta", {})
            row: dict[str, Any] = {
                "uid": uid,
                "title": hit.get("title", ""),
                "folder": hit.get("folderTitle") or "General",
                "action": "relink",
                "relinked": stats.relinked,
                "relinked_ds": stats.relinked_ds,
                "goto_links": " | ".join(stats.goto_links),
            }
            if meta.get("provisioned"):
                row.update(action="skip", reason="provisioned: fix it in its own repository")
            else:
                try:
                    schema = stored_schema(dst, namespace, uid)
                except GrafanaError as exc:
                    console.print(f"[red]Cannot read the stored schema of {uid}:[/red] {exc}")
                    console.print("On Grafana Cloud pass --namespace stacks-<stack id>.")
                    raise typer.Exit(2) from exc
                if not schema:
                    row.update(action="skip", reason="stored schema unknown: not saved, check it by hand")
                elif schema.startswith("v2"):
                    row.update(
                        action="skip",
                        reason=f"stored as {schema}: /api/dashboards would save it as v1, fix it by hand",
                    )
            if row["action"] == "relink":
                # Target version kept: a save made meanwhile fails with 412 instead of being lost.
                target = payload_dir / f"{uid}.json"
                target.write_text(
                    json.dumps(
                        {
                            "dashboard": dashboard,
                            "folderUid": meta.get("folderUid", ""),
                            "overwrite": False,
                            "message": f"relink: {src_host} -> {dst.host}",
                        },
                        indent=2,
                        ensure_ascii=False,
                    ),
                    encoding="utf-8",
                )
                row["payload"] = str(target)
            report.append(row)

    report_path = out / "relink.csv"
    fields = [
        "uid", "title", "folder", "action", "reason", "relinked", "relinked_ds", "goto_links", "payload",
    ]
    with report_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(report)

    todo = [r for r in report if r["action"] == "relink"]
    gotos = sum(len(r["goto_links"].split(" | ")) for r in report if r["goto_links"])
    console.print(
        f"{len(report)} dashboards link to {src_host}: {len(todo)} to relink, "
        f"{len(report) - len(todo)} skipped, "
        f"{sum(r['relinked'] for r in report)} links, {sum(r['relinked_ds'] for r in report)} datasource uids"
    )
    if gotos:
        console.print(f"[yellow]{gotos} /goto/ short links cannot be repointed[/yellow]: recreate them.")
    console.print(f"report -> [cyan]{report_path}[/cyan]")
    if not apply_changes or not todo:
        return
    if not yes and not typer.confirm(f"Save {len(todo)} dashboards on {dst.base_url}?"):
        raise typer.Exit(1)

    failures: list[tuple[str, str]] = []
    for row in todo:
        try:
            dst.post("/api/dashboards/db", json.loads(Path(row["payload"]).read_text(encoding="utf-8")))
        except GrafanaError as exc:
            failures.append((row["uid"], str(exc)))
    console.print(f"[green]{len(todo) - len(failures)} dashboards relinked[/green]")
    if failures:
        console.print(f"[red]{len(failures)} failures[/red] (412 means saved meanwhile: rerun):")
        for uid, err in failures[:20]:
            console.print(f"  {uid}: {err}")
        raise typer.Exit(1)


# --------------------------------------------------------------------------- #
# Library panels
# --------------------------------------------------------------------------- #


def fetch_library_elements(client: GrafanaClient) -> list[dict[str, Any]]:
    """Page through every library element on an instance."""
    out: list[dict[str, Any]] = []
    page = 1
    while True:
        body = client.get("/api/library-elements", params={"perPage": 100, "page": page}) or {}
        result = body.get("result") or {}
        batch = result.get("elements") if isinstance(result, dict) else None
        if batch is None:
            batch = body.get("elements") or []
        if not batch:
            break
        out.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return out


def rewrite_library_element(
    element: dict[str, Any], resolver: Resolver
) -> tuple[dict[str, Any], RewriteStats]:
    """Return a target-ready library element payload plus its rewrite report.

    The uid is preserved: a dashboard references a library panel by uid, so an
    element recreated under a new uid leaves every dashboard using it broken.
    """
    stats = RewriteStats()
    model = _walk(element.get("model") or {}, resolver, stats, "model")
    payload = {
        "uid": element.get("uid"),
        "name": element.get("name"),
        "kind": element.get("kind", 1),
        "folderUid": element.get("folderUid") or "",
        "model": model,
    }
    return payload, stats



# --------------------------------------------------------------------------- #
# Pruning what the migration itself pushed
# --------------------------------------------------------------------------- #

# Refuse to prune when the source listing looks truncated: a half-failed search
# would make the whole manifest look deleted.
MIN_SOURCE_RATIO = 0.5


def load_manifest(out: Path) -> dict[str, str]:
    """Return every dashboard uid this tool has pushed, mapped to a readable label.

    ``state.json`` is authoritative once an apply has written it. Before that,
    the plan report and the rollback manifest together cover what went out.

    This mapping is what makes pruning safe: a dashboard created directly on the
    target appears in no manifest, so it is invisible here by construction rather
    than by a filter someone could forget.
    """
    manifest: dict[str, str] = {}
    state = load_state(out / "state.json")
    for uid, rec in state.items():
        if isinstance(rec, dict):
            manifest[uid] = str(rec.get("title") or uid)

    plan = out / "plan.csv"
    if plan.exists():
        with plan.open(newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                if row.get("uid") and row.get("action") in {"create", "update"}:
                    manifest.setdefault(row["uid"], f"{row.get('folder','')}/{row.get('title','')}")

    rollback = out / "rollback.json"
    if rollback.exists():
        try:
            data = json.loads(rollback.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        for uid in data.get("dashboards", []) or []:
            manifest.setdefault(uid, uid)
    return manifest


def prune_candidates(
    manifest: dict[str, str], source_uids: set[str], target_uids: set[str]
) -> list[str]:
    """Return the uids this tool pushed, still on the target, gone from the source.

    Everything outside the manifest is left alone, whoever created it.
    """
    return sorted(uid for uid in manifest if uid in target_uids and uid not in source_uids)


@app.command()
def prune(
    out: OutDir = DEFAULT_OUT,
    max_deletions: Annotated[
        int, typer.Option("--max", help="Abort when more than this many dashboards match.")
    ] = 50,
    apply_changes: Annotated[
        bool, typer.Option("--apply", help="Delete them. Without it this only reports.")
    ] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Do not ask for confirmation.")] = False,
) -> None:
    """Delete target dashboards this tool pushed that have since gone from the source.

    Dashboards created directly on the target are never touched: they appear in no
    manifest, so this command cannot see them.
    """
    src, dst = make_clients()
    manifest = load_manifest(out)
    if not manifest:
        console.print(f"[red]No manifest in {out}.[/red] Run `plan` and `apply` first.")
        raise typer.Exit(2)

    source_uids = {h["uid"] for h in src.search("dash-db")}
    target_hits = dst.search("dash-db")
    target_uids = {h["uid"] for h in target_hits}
    labels = {h["uid"]: f"{h.get('folderTitle') or 'General'}/{h.get('title')}" for h in target_hits}

    console.print(
        f"manifest: {len(manifest)} pushed   source: {len(source_uids)}   target: {len(target_uids)}"
    )
    native = len(target_uids - set(manifest))
    console.print(
        f"[dim]{native} dashboards on the target came from somewhere else "
        "and are off limits.[/dim]"
    )

    if len(source_uids) < len(manifest) * MIN_SOURCE_RATIO:
        console.print(
            f"[red]The source lists {len(source_uids)} dashboards against {len(manifest)} pushed.[/red] "
            "That looks like a truncated listing rather than a cleanup. Refusing to prune."
        )
        raise typer.Exit(1)

    candidates = prune_candidates(manifest, source_uids, target_uids)
    if not candidates:
        console.print("[green]Nothing to prune.[/green]")
        return

    table = Table(title=f"{len(candidates)} dashboards deleted from the source, still on the target")
    table.add_column("dashboard")
    table.add_column("uid")
    for uid in candidates:
        table.add_row(labels.get(uid, manifest[uid])[:56], uid)
    console.print(table)

    if len(candidates) > max_deletions:
        console.print(
            f"[red]{len(candidates)} matches, over the --max of {max_deletions}.[/red] "
            "Raise it deliberately if this really is the cleanup you expect."
        )
        raise typer.Exit(1)
    if not apply_changes:
        console.print("Dry run. Pass [bold]--apply[/bold] to delete them.")
        return

    # Saved from the target, not the source: the source copy is gone by definition.
    backup_dir = out / "prune_backup"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    saved = []
    for uid in candidates:
        envelope = dst.get_dashboard(uid)
        if envelope:
            saved.append(envelope)
    backup = backup_dir / f"pruned_{stamp}.json"
    backup.write_text(json.dumps(saved, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"backup of {len(saved)} dashboards -> [cyan]{backup}[/cyan]")

    if not yes and not typer.confirm(f"Delete {len(candidates)} dashboards from {dst.base_url}?"):
        raise typer.Exit(1)

    failures: list[tuple[str, str]] = []
    for uid in candidates:
        try:
            dst.delete(f"/api/dashboards/uid/{uid}", allow_404=True)
        except GrafanaError as exc:
            failures.append((uid, str(exc)))
    console.print(f"[green]{len(candidates) - len(failures)} dashboards deleted[/green]")
    if failures:
        for uid, err in failures[:10]:
            console.print(f"  {uid}: {err}")
        raise typer.Exit(1)

@app.command("library-panels")
def library_panels(
    out: OutDir = DEFAULT_OUT,
    apply_changes: Annotated[
        bool, typer.Option("--apply", help="Write to the target. Without it this only reports.")
    ] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Do not ask for confirmation.")] = False,
) -> None:
    """Copy the library panels, keeping their uid so dashboards find them again.

    Run this BEFORE the dashboards that use them: a dashboard imported while its
    library panel is missing renders "Unable to load library panel".
    """
    src, dst = make_clients()
    rows = load_or_build_map(src, dst, out)
    resolver = Resolver(rows)

    elements = fetch_library_elements(src)
    existing = {e.get("uid"): e for e in fetch_library_elements(dst)}
    console.print(f"{len(elements)} library panels on source, {len(existing)} on target")

    payloads: list[tuple[dict[str, Any], RewriteStats, bool]] = []
    blocked = 0
    for element in elements:
        payload, stats = rewrite_library_element(element, resolver)
        if not stats.ok:
            blocked += 1
        payloads.append((payload, stats, payload["uid"] in existing))

    table = Table(title="Library panels")
    for column in ("name", "type", "datasources", "state"):
        table.add_column(column)
    for (payload, stats, present), element in zip(payloads, elements, strict=True):
        if not stats.ok:
            state = "[red]blocked[/red]"
        elif present:
            state = "update"
        else:
            state = "create"
        table.add_row(
            str(payload["name"])[:44],
            str(element.get("type", "")),
            f"{stats.rewritten} rewritten, {stats.already_correct} kept",
            state,
        )
    console.print(table)

    report = out / "library_panels.csv"
    report.parent.mkdir(parents=True, exist_ok=True)
    with report.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["uid", "name", "type", "state", "rewritten", "unresolved", "dropped"])
        for (payload, stats, present), element in zip(payloads, elements, strict=True):
            writer.writerow([
                payload["uid"], payload["name"], element.get("type", ""),
                "blocked" if not stats.ok else ("update" if present else "create"),
                stats.rewritten, " | ".join(stats.unresolved), " | ".join(stats.dropped),
            ])
    console.print(f"report -> [cyan]{report}[/cyan]")

    if blocked:
        console.print(
            f"[red]{blocked} library panels reference a datasource with no target mapping.[/red] "
            "They are not written; fix the datasource map first."
        )
    if not apply_changes:
        console.print("Dry run. Pass [bold]--apply[/bold] to write them to the target.")
        return

    writable = [(p, s, e) for (p, s, e) in payloads if s.ok]
    if not yes and not typer.confirm(f"Write {len(writable)} library panels to {dst.base_url}?"):
        raise typer.Exit(1)

    failures: list[tuple[str, str]] = []
    for payload, _stats, present in writable:
        try:
            if present:
                # The update endpoint takes the target's current version, not the source's.
                body = dict(payload)
                body["version"] = existing[payload["uid"]].get("version", 1)
                dst.request("PATCH", f"/api/library-elements/{payload['uid']}", json_body=body)
            else:
                dst.post("/api/library-elements", payload)
        except GrafanaError as exc:
            failures.append((str(payload["name"]), str(exc)))

    console.print(f"[green]{len(writable) - len(failures)} library panels written[/green]")
    console.print(
        "Dashboards reference them by uid, so the ones already on the target should render now. "
        "Re-run apply on those dashboards to register the usage links Grafana shows under "
        "\"Connected dashboards\"."
    )
    if failures:
        for name, err in failures[:20]:
            console.print(f"  {name}: {err}")
        raise typer.Exit(1)


# --------------------------------------------------------------------------- #
# Annotations, playlists, org preferences
# --------------------------------------------------------------------------- #

# The annotations endpoint caps a single response, so history is walked in slices.
ANNOTATION_PAGE = 1000
SLICE_DAYS = 30


def is_robot(annotation: dict[str, Any]) -> bool:
    """True when an annotation was posted by a service account rather than a person.

    Deployment markers are written continuously by CI and are worthless once the
    pipeline is repointed at the new instance; hand-written notes are not.
    """
    return str(annotation.get("login") or "").startswith("sa-")


def annotation_key(annotation: dict[str, Any]) -> tuple[Any, ...]:
    """Identity of an annotation across instances, since ids are instance-local."""
    return (
        annotation.get("dashboardUID") or "",
        annotation.get("panelId") or 0,
        annotation.get("time") or 0,
        (annotation.get("text") or "").strip(),
    )


def fetch_annotations(client: GrafanaClient, months: int) -> list[dict[str, Any]]:
    """Walk annotation history backwards in slices, newest first."""
    now = int(time.time() * 1000)
    slice_ms = SLICE_DAYS * 86400 * 1000
    seen: dict[tuple[Any, ...], dict[str, Any]] = {}
    for step in range(max(1, (months * 30) // SLICE_DAYS)):
        end = now - step * slice_ms
        start = end - slice_ms
        batch = client.get(
            "/api/annotations",
            params={"limit": ANNOTATION_PAGE, "type": "annotation", "from": start, "to": end},
        ) or []
        for item in batch:
            seen.setdefault(annotation_key(item), item)
    return sorted(seen.values(), key=lambda a: a.get("time") or 0)


@app.command()
def annotations(
    out: OutDir = DEFAULT_OUT,
    months: Annotated[int, typer.Option("--months", help="How far back to walk.")] = 24,
    include_bots: Annotated[
        bool,
        typer.Option("--include-bots", help="Also copy annotations posted by service accounts."),
    ] = False,
    apply_changes: Annotated[
        bool, typer.Option("--apply", help="Write to the target. Without it this only reports.")
    ] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Do not ask for confirmation.")] = False,
) -> None:
    """Copy the hand-written dashboard annotations, skipping CI deployment markers."""
    src, dst = make_clients()
    found = fetch_annotations(src, months)
    robots = [a for a in found if is_robot(a)]
    wanted = found if include_bots else [a for a in found if not is_robot(a)]
    console.print(
        f"{len(found)} annotations over ~{months} months: "
        f"{len(robots)} from service accounts, {len(found) - len(robots)} from people"
    )
    if robots and not include_bots:
        console.print(
            "[dim]Service account annotations are skipped: repoint the pipeline that writes "
            "them at the target instead of copying its backlog.[/dim]"
        )

    existing = {annotation_key(a) for a in fetch_annotations(dst, months)}
    todo = [a for a in wanted if annotation_key(a) not in existing]
    console.print(f"{len(todo)} to copy, {len(wanted) - len(todo)} already on the target")

    report = out / "annotations.csv"
    report.parent.mkdir(parents=True, exist_ok=True)
    with report.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["time", "author", "dashboard_uid", "panel_id", "text", "tags", "state"])
        for a in wanted:
            writer.writerow([
                a.get("time"), a.get("login", ""), a.get("dashboardUID", ""), a.get("panelId", ""),
                (a.get("text") or "").replace("\n", " ")[:200], "|".join(a.get("tags") or []),
                "copy" if annotation_key(a) not in existing else "present",
            ])
    console.print(f"report -> [cyan]{report}[/cyan]")

    if not apply_changes:
        console.print("Dry run. Pass [bold]--apply[/bold] to write them to the target.")
        return
    if not todo:
        return
    console.print(
        "[yellow]The target records the importing account as the author[/yellow], not the "
        "original one: the API has no way to attribute an annotation to someone else."
    )
    if not yes and not typer.confirm(f"Copy {len(todo)} annotations to {dst.base_url}?"):
        raise typer.Exit(1)

    failures: list[tuple[str, str]] = []
    for a in todo:
        body = {
            "dashboardUID": a.get("dashboardUID"),
            "panelId": a.get("panelId"),
            "time": a.get("time"),
            "timeEnd": a.get("timeEnd") or a.get("time"),
            "tags": a.get("tags") or [],
            "text": a.get("text") or "",
        }
        try:
            dst.post("/api/annotations", body)
        except GrafanaError as exc:
            failures.append((str(a.get("id")), str(exc)))
    console.print(f"[green]{len(todo) - len(failures)} annotations copied[/green]")
    if failures:
        for name, err in failures[:10]:
            console.print(f"  {name}: {err}")
        raise typer.Exit(1)


@app.command()
def playlists(
    apply_changes: Annotated[
        bool, typer.Option("--apply", help="Write to the target. Without it this only reports.")
    ] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Do not ask for confirmation.")] = False,
) -> None:
    """Copy the playlists.

    Organisation preferences are deliberately not handled here: manage them as
    code, for example with the Terraform ``grafana_organization_preferences``
    resource. Two owners for one setting would fight on every apply.
    """
    src, dst = make_clients()
    source_playlists = src.get("/api/playlists", params={"perpage": 500}) or []
    detailed = [src.get(f"/api/playlists/{p['uid']}") or {} for p in source_playlists]
    on_target = {p.get("uid") for p in (dst.get("/api/playlists", params={"perpage": 500}) or [])}

    table = Table(title="Playlists")
    for column in ("name", "content", "state"):
        table.add_column(column)
    for pl in detailed:
        table.add_row(
            str(pl.get("name")),
            f"{len(pl.get('items') or [])} dashboards, every {pl.get('interval')}",
            "exists" if pl.get("uid") in on_target else "create",
        )
    console.print(table)

    prefs = src.get("/api/org/preferences") or {}
    console.print(
        f"[dim]Source organisation preferences are {json.dumps(prefs)}. Not applied here: "
        "manage them as code, e.g. Terraform grafana_organization_preferences.[/dim]"
    )

    if not apply_changes:
        console.print("Dry run. Pass [bold]--apply[/bold] to write them to the target.")
        return
    todo = [pl for pl in detailed if pl.get("uid") not in on_target]
    if not todo:
        console.print("Nothing to do.")
        return
    if not yes and not typer.confirm(f"Create {len(todo)} playlists on {dst.base_url}?"):
        raise typer.Exit(1)

    for pl in todo:
        # Playlist items point at dashboards by uid, which the migration preserves.
        dst.post(
            "/api/playlists",
            {
                "uid": pl.get("uid"),
                "name": pl.get("name"),
                "interval": pl.get("interval"),
                "items": pl.get("items") or [],
            },
        )
    console.print(f"[green]{len(todo)} playlists created[/green]")

@app.command("alerts-plan")
def alerts_plan(
    out: OutDir = DEFAULT_OUT,
    folder: FolderOpt = None,
    exclude: ExcludeOpt = None,
    limit: LimitOpt = 0,
    force: Annotated[
        bool,
        typer.Option("--force", help="Replan everything, ignoring what the last apply pushed."),
    ] = False,
) -> None:
    """Build the alert-rule payloads on disk without writing anything to the target."""
    src, dst = make_clients()
    rows = load_or_build_map(src, dst, out)
    resolver = Resolver(rows)
    adir = out / "alerts"
    adir.mkdir(parents=True, exist_ok=True)

    rules = src.get("/api/v1/provisioning/alert-rules") or []
    folders = fetch_folders(src)
    titles = {uid: f.title for uid, f in folders.items()}
    excl = [re.compile(p) for p in (exclude or [])]

    report: list[dict[str, Any]] = []
    kept: list[dict[str, Any]] = []
    state = {} if force else load_state(adir / "state.json")
    for rule in rules:
        ftitle = titles.get(rule.get("folderUID") or "", rule.get("folderUID") or "")
        if folder and ftitle not in folder:
            continue
        if any(p.search(ftitle) or p.search(rule.get("title", "")) for p in excl):
            continue
        kept.append(rule)
    kept.sort(
        key=lambda r: (
            titles.get(r.get("folderUID") or "", ""),
            r.get("ruleGroup", ""),
            r.get("title", ""),
        )
    )
    if limit:
        kept = kept[:limit]

    console.print(f"{len(kept)} of {len(rules)} alert rules selected")
    frozen = unchanged_rule_groups([r for r in kept if not r.get("provenance")], state)
    if frozen:
        console.print(f"{len(frozen)} rule groups unchanged since the last apply, skipped whole")
    relinked_total = 0
    for rule in kept:
        ftitle = titles.get(rule.get("folderUID") or "", rule.get("folderUID") or "")
        if rule.get("provenance"):
            report.append({
                "uid": rule.get("uid", ""), "title": rule.get("title", ""), "folder": ftitle,
                "group": rule.get("ruleGroup", ""), "action": "skip",
                "reason": f"provisioned ({rule['provenance']}): redeploy from its own pipeline",
            })
            continue
        if (rule.get("folderUID") or "", rule.get("ruleGroup") or "") in frozen:
            report.append({
                "uid": rule.get("uid", ""), "title": rule.get("title", ""), "folder": ftitle,
                "group": rule.get("ruleGroup", ""), "action": "skip",
                "reason": "group unchanged since last apply",
                "src_updated": rule.get("updated", ""),
            })
            continue

        new, stats, relinked = rewrite_alert_rule(rule, resolver, src.host, dst.host)
        relinked_total += relinked
        path = adir / "rules" / _safe(ftitle) / f"{_safe(rule.get('title', ''))}.{rule.get('uid')}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(new, indent=2, ensure_ascii=False), encoding="utf-8")
        report.append({
            "uid": rule.get("uid", ""), "title": rule.get("title", ""), "folder": ftitle,
            "group": rule.get("ruleGroup", ""),
            "action": "BLOCKED" if not stats.ok else "push",
            "was_paused": rule.get("isPaused", False),
            "receiver": receiver_of(rule) or "",
            "rewritten": stats.rewritten, "already_correct": stats.already_correct,
            "relinked_annotations": relinked,
            "src_updated": rule.get("updated", ""),
            "unresolved": " | ".join(stats.unresolved),
            "dropped": " | ".join(stats.dropped),
            "dangling": " | ".join(stats.dangling),
            "payload": str(path),
        })

    fields = ["uid", "title", "folder", "group", "action", "reason", "was_paused", "receiver",
              "rewritten", "already_correct", "relinked_annotations", "src_updated",
              "unresolved", "dropped", "dangling", "payload"]
    plan_path = adir / "plan.csv"
    with plan_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(report)

    pushable = [r for r in report if r["action"] == "push"]
    groups = fetch_rule_groups(src, [r for r in kept if not r.get("provenance")])
    groups_path = adir / "groups.csv"
    with groups_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["folder_uid", "folder", "group", "interval_seconds"])
        for (fuid, gname), grp in sorted(groups.items()):
            writer.writerow([fuid, titles.get(fuid, fuid), gname, grp.interval])

    # Contact points the rules route to directly. They must exist before the rules.
    wanted = Counter(r["receiver"] for r in pushable if r["receiver"])
    existing = {c.get("name") for c in (dst.get("/api/v1/provisioning/contact-points") or [])}
    missing = {name: n for name, n in wanted.items() if name not in existing}

    # Routing that is not scripted: exported for review, never applied.
    for name, path in (
        ("policies", "notification_policy.json"),
        ("mute-timings", "mute_timings.json"),
        ("templates", "templates.json"),
    ):
        data = src.get(f"/api/v1/provisioning/{name}", allow_404=True)
        (adir / path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    summary = Table(title="Alert rules plan")
    summary.add_column("action")
    summary.add_column("count", justify="right")
    for action, count in Counter(r["action"] for r in report).most_common():
        summary.add_row(action, str(count))
    console.print(summary)
    console.print(
        f"{len(groups)} rule groups, {relinked_total} annotation links repointed to {dst.host}"
    )
    console.print(f"payloads -> [cyan]{adir / 'rules'}[/cyan]\nreport   -> [cyan]{plan_path}[/cyan]")

    if missing:
        miss = Table(title="Contact points missing on the target")
        miss.add_column("rules", justify="right")
        miss.add_column("receiver")
        for name, n in sorted(missing.items(), key=lambda kv: -kv[1]):
            miss.add_row(str(n), name)
        console.print(miss)
        console.print("Run [bold]alerts-contacts[/bold] first, or those rules will not notify.")
    console.print(
        f"Routing exported to [cyan]{adir}[/cyan]. Push it with [bold]alerts-routing[/bold] "
        "before the rules: it replaces the target's whole routing tree in one call, so it "
        "snapshots the current one first."
    )


@app.command("alerts-apply")
def alerts_apply(
    out: OutDir = DEFAULT_OUT,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Do not ask for confirmation.")] = False,
    skip_blocked: Annotated[
        bool, typer.Option("--skip-blocked", help="Skip blocked rules instead of aborting.")
    ] = False,
) -> None:
    """Push the alert rules to the target, paused, one rule group at a time."""
    src, dst = make_clients()
    adir = out / "alerts"
    plan_path = adir / "plan.csv"
    if not plan_path.exists():
        console.print(f"[red]No alert plan at {plan_path}.[/red] Run `alerts-plan` first.")
        raise typer.Exit(2)

    with plan_path.open(newline="", encoding="utf-8") as fh:
        planned = list(csv.DictReader(fh))
    blocked = [r for r in planned if r["action"] == "BLOCKED"]
    todo = [r for r in planned if r["action"] == "push"]
    if blocked and not skip_blocked:
        console.print(f"[red]{len(blocked)} rules blocked on unresolved datasources.[/red]")
        console.print(f"Fix {out / 'datasource_map.csv'} and rerun `alerts-plan`, or --skip-blocked.")
        raise typer.Exit(1)

    intervals: dict[tuple[str, str], int] = {}
    with (adir / "groups.csv").open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            intervals[(row["folder_uid"], row["group"])] = int(row["interval_seconds"])

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    stamps: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in todo:
        rule = json.loads(Path(row["payload"]).read_text(encoding="utf-8"))
        key = (rule.get("folderUID", ""), rule.get("ruleGroup", ""))
        grouped[key].append(rule)
        stamps[key].append(
            {"uid": row["uid"], "updated": row.get("src_updated", ""), "title": row.get("title", "")}
        )

    console.print(f"Target: [bold]{dst.base_url}[/bold]")
    console.print(f"{len(todo)} rules across {len(grouped)} groups")
    console.print(
        "[yellow]Every rule is pushed PAUSED.[/yellow] Nothing pages until you unpause it, "
        "and unpausing is what makes the old instance's copy a duplicate: disable it there "
        "at the same time."
    )
    if blocked:
        console.print(f"[yellow]{len(blocked)} blocked rules will be skipped.[/yellow]")
    if not yes and not typer.confirm("Write these alert rules to the target?"):
        raise typer.Exit(1)

    folders = fetch_folders(src)
    needed = {uid: folders[uid] for uid, _ in grouped if uid in folders}
    frontier = list(needed.values())
    while frontier:
        current = frontier.pop()
        parent = current.parent_uid
        if parent and parent in folders and parent not in needed:
            needed[parent] = folders[parent]
            frontier.append(folders[parent])
    created_folders: list[str] = []
    for f in order_folders(needed):
        if dst.get_folder(f.uid) is not None:
            continue
        body: dict[str, Any] = {"uid": f.uid, "title": f.title}
        if f.parent_uid:
            body["parentUid"] = f.parent_uid
        dst.post("/api/folders", body)
        created_folders.append(f.uid)

    failures: list[tuple[str, str]] = []
    written: list[dict[str, str]] = []
    state_path = adir / "state.json"
    state = load_state(state_path)
    with Progress(
        SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("applying", total=len(grouped))
        for (fuid, gname), rules in sorted(grouped.items()):
            progress.update(task, description=f"group {gname[:40]}")
            body = {
                "title": gname,
                "folderUid": fuid,
                "interval": intervals.get((fuid, gname), 60),
                "rules": rules,
            }
            try:
                dst.put(
                    f"/api/v1/provisioning/folder/{fuid}/rule-groups/{gname}",
                    body,
                    headers=NO_PROVENANCE,
                )
                written.append({"folder_uid": fuid, "group": gname})
                # The whole group landed, so every rule in it is now on the target.
                for stamp in stamps[(fuid, gname)]:
                    if stamp["updated"]:
                        state[stamp["uid"]] = {
                            "updated": stamp["updated"],
                            "title": stamp["title"],
                            "group": gname,
                        }
            except GrafanaError as exc:
                failures.append((f"{fuid}/{gname}", str(exc)))
            progress.advance(task)

    state_path.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    manifest = adir / "rollback.json"
    manifest.write_text(
        json.dumps({"rule_groups": written, "folders": created_folders}, indent=2),
        encoding="utf-8",
    )
    console.print(
        f"\n[green]{len(written)} rule groups written[/green], all rules paused. "
        f"rollback -> [cyan]{manifest}[/cyan]"
    )
    console.print(f"{len(state)} rules recorded in [cyan]{state_path}[/cyan]")
    if failures:
        console.print(f"[red]{len(failures)} failures:[/red]")
        for name, err in failures[:20]:
            console.print(f"  {name}: {err}")
        raise typer.Exit(1)


@app.command("alerts-contacts")
def alerts_contacts(
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Do not ask for confirmation.")] = False,
) -> None:
    """Copy the contact points, secrets included, straight from source to target.

    The decrypted export is held in memory and never written to disk: it carries
    live Slack webhooks and paging keys.
    """
    src, dst = make_clients()
    try:
        export = src.get("/api/v1/provisioning/contact-points/export", params={"decrypt": "true"})
    except GrafanaError as exc:
        if "403" not in str(exc):
            raise
        console.print("[red]The source token cannot read contact point secrets.[/red]")
        console.print(
            "Grant [bold]alert.provisioning.secrets:read[/bold] to the source service account "
            '(fixed role "Alerting provisioning secrets reader"), run this, then revoke it.'
        )
        raise typer.Exit(2) from exc

    receivers: list[dict[str, Any]] = []
    for point in (export or {}).get("contactPoints", []):
        for receiver in point.get("receivers", []):
            receivers.append({
                "name": point.get("name"),
                "type": receiver.get("type"),
                "settings": receiver.get("settings") or {},
                "disableResolveMessage": receiver.get("disableResolveMessage", False),
                "uid": receiver.get("uid"),
            })

    still_redacted = [r for r in receivers if "[REDACTED]" in json.dumps(r["settings"])]
    existing = {c.get("name") for c in (dst.get("/api/v1/provisioning/contact-points") or [])}

    table = Table(title=f"{len(receivers)} contact points to copy to {dst.host}")
    table.add_column("type")
    table.add_column("name")
    table.add_column("status")
    for r in receivers:
        state = "exists on target" if r["name"] in existing else "new"
        if "[REDACTED]" in json.dumps(r["settings"]):
            state = "[red]still redacted[/red]"
        table.add_row(str(r["type"]), str(r["name"])[:40], state)
    console.print(table)

    if still_redacted:
        console.print(
            f"[red]{len(still_redacted)} contact points came back redacted anyway.[/red] "
            "They would be created unable to notify. Fix the permission or enter them by hand."
        )
        raise typer.Exit(1)

    console.print("[yellow]These payloads carry live webhooks and paging keys.[/yellow]")
    if not yes and not typer.confirm(f"Create them on {dst.base_url}?"):
        raise typer.Exit(1)

    failures: list[tuple[str, str]] = []
    for r in receivers:
        try:
            dst.post("/api/v1/provisioning/contact-points", r, headers=NO_PROVENANCE)
        except GrafanaError as exc:
            failures.append((str(r["name"]), str(exc)))
    console.print(f"[green]{len(receivers) - len(failures)} contact points created[/green]")
    if failures:
        for name, err in failures[:20]:
            console.print(f"  {name}: {err}")
        raise typer.Exit(1)


def receivers_in_tree(node: dict[str, Any]) -> set[str]:
    """Return every contact point name the routing tree sends to, at any depth."""
    found: set[str] = set()
    name = node.get("receiver")
    if isinstance(name, str) and name:
        found.add(name)
    for child in node.get("routes") or []:
        if isinstance(child, dict):
            found |= receivers_in_tree(child)
    return found


def mute_timings_in_tree(node: dict[str, Any]) -> set[str]:
    """Return every mute timing the routing tree references, at any depth."""
    found = {m for m in (node.get("mute_time_intervals") or []) if isinstance(m, str)}
    for child in node.get("routes") or []:
        if isinstance(child, dict):
            found |= mute_timings_in_tree(child)
    return found


@app.command("alerts-routing")
def alerts_routing(
    out: OutDir = DEFAULT_OUT,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Do not ask for confirmation.")] = False,
) -> None:
    """Copy the templates, mute timings and notification policy tree to the target.

    The tree is a single object: pushing it replaces the target's entire routing in
    one call. The current target tree is snapshotted first so `alerts-rollback` can
    put it back, and every contact point the tree sends to must already exist.
    """
    src, dst = make_clients()
    adir = out / "alerts"
    adir.mkdir(parents=True, exist_ok=True)

    templates = src.get("/api/v1/provisioning/templates") or []
    timings = src.get("/api/v1/provisioning/mute-timings") or []
    tree = src.get("/api/v1/provisioning/policies") or {}

    wanted = receivers_in_tree(tree)
    existing = {c.get("name") for c in (dst.get("/api/v1/provisioning/contact-points") or [])}
    missing = sorted(wanted - existing)
    if missing:
        console.print(f"[red]{len(missing)} contact points referenced by the tree are missing:[/red]")
        for name in missing[:20]:
            console.print(f"  {name}")
        console.print("Run [bold]alerts-contacts[/bold] first: routing to a missing receiver fails.")
        raise typer.Exit(1)

    needed_timings = mute_timings_in_tree(tree)
    have_timings = {t.get("name") for t in timings}
    if needed_timings - have_timings:
        console.print(
            f"[red]The tree references mute timings absent from the source:[/red] "
            f"{', '.join(sorted(needed_timings - have_timings))}"
        )
        raise typer.Exit(1)

    backup_path = adir / "routing_backup.json"
    backup = dst.get("/api/v1/provisioning/policies", allow_404=True)
    backup_path.write_text(json.dumps(backup, indent=2, ensure_ascii=False), encoding="utf-8")

    console.print(f"Target: [bold]{dst.base_url}[/bold]")
    console.print(
        f"{len(templates)} templates, {len(timings)} mute timings, "
        f"{len(tree.get('routes') or [])} root routes sending to {len(wanted)} contact points"
    )
    console.print(
        f"[yellow]This replaces the target's whole routing tree.[/yellow] Its current state "
        f"({len(((backup or {}).get('routes')) or [])} root routes) is saved to {backup_path}."
    )
    if not yes and not typer.confirm("Replace the target routing?"):
        raise typer.Exit(1)

    # Templates and mute timings first: the tree may reference them by name.
    for tpl in templates:
        dst.put(
            f"/api/v1/provisioning/templates/{tpl['name']}",
            {"template": tpl.get("template", "")},
            headers=NO_PROVENANCE,
        )
    for timing in timings:
        existing_timing = dst.get(
            f"/api/v1/provisioning/mute-timings/{timing['name']}", allow_404=True
        )
        if existing_timing is None:
            dst.post("/api/v1/provisioning/mute-timings", timing, headers=NO_PROVENANCE)
        else:
            dst.put(
                f"/api/v1/provisioning/mute-timings/{timing['name']}",
                timing,
                headers=NO_PROVENANCE,
            )
    dst.put("/api/v1/provisioning/policies", tree, headers=NO_PROVENANCE)

    console.print(
        f"[green]routing applied[/green]: {len(templates)} templates, {len(timings)} mute "
        f"timings, tree with {len(tree.get('routes') or [])} root routes"
    )


@app.command("alerts-rollback")
def alerts_rollback(
    out: OutDir = DEFAULT_OUT,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Do not ask for confirmation.")] = False,
) -> None:
    """Undo the last alerts-apply, and restore the routing alerts-routing replaced."""
    _, dst = make_clients()
    adir = out / "alerts"
    manifest_path = adir / "rollback.json"
    backup_path = adir / "routing_backup.json"
    if not manifest_path.exists() and not backup_path.exists():
        console.print(f"[red]Nothing to roll back: no manifest in {adir}.[/red]")
        raise typer.Exit(2)

    manifest = (
        json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    )
    groups = manifest.get("rule_groups", [])
    folders = manifest.get("folders", [])

    console.print(f"Target: [bold]{dst.base_url}[/bold]")
    console.print(f"[yellow]Will delete {len(groups)} rule groups.[/yellow]")
    if backup_path.exists():
        console.print("[yellow]Will restore the routing tree saved before alerts-routing.[/yellow]")
    if folders:
        console.print(f"Will also remove up to {len(folders)} folders, but only empty ones.")
    if not yes and not typer.confirm("Roll back?"):
        raise typer.Exit(1)

    for group in groups:
        dst.delete(
            f"/api/v1/provisioning/folder/{group['folder_uid']}/rule-groups/{group['group']}",
            allow_404=True,
        )

    if backup_path.exists():
        backup = json.loads(backup_path.read_text(encoding="utf-8"))
        if backup:
            dst.put("/api/v1/provisioning/policies", backup, headers=NO_PROVENANCE)
        else:
            # No tree existed before: reset to the stock one rather than leave ours.
            dst.delete("/api/v1/provisioning/policies", allow_404=True)

    # A folder created for the rules may since have received dashboards. Deleting it
    # would take them with it, so anything non-empty is left alone.
    kept = 0
    for uid in reversed(folders):
        hits = dst.get("/api/search", params={"folderUIDs": uid, "limit": 1}) or []
        rules = dst.get(f"/api/v1/provisioning/folder/{uid}/rule-groups", allow_404=True)
        if hits or rules:
            kept += 1
            continue
        dst.delete(f"/api/folders/{uid}", allow_404=True)

    console.print(f"[green]{len(groups)} rule groups deleted[/green]")
    if kept:
        console.print(f"{kept} folders kept: they are not empty any more")

@app.command()
def rollback(
    out: OutDir = DEFAULT_OUT,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Do not ask for confirmation.")] = False,
) -> None:
    """Delete everything the last apply created on the target, newest first."""
    _, dst = make_clients()
    path = out / "rollback.json"
    if not path.exists():
        console.print(f"[red]No rollback manifest at {path}.[/red]")
        raise typer.Exit(2)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    dashboards = manifest.get("dashboards", [])
    folders = manifest.get("folders", [])

    console.print(f"Target: [bold]{dst.base_url}[/bold]")
    console.print(
        f"[yellow]Will delete {len(dashboards)} dashboards and "
        f"{len(folders)} folders created by the last apply.[/yellow]"
    )
    if not yes and not typer.confirm("Delete them?"):
        raise typer.Exit(1)

    for uid in dashboards:
        dst.delete(f"/api/dashboards/uid/{uid}", allow_404=True)
    for uid in reversed(folders):
        dst.delete(f"/api/folders/{uid}", allow_404=True)
    console.print("[green]rollback done[/green]")


if __name__ == "__main__":
    app()
