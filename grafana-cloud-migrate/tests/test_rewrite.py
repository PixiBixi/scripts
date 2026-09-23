"""Tests for the datasource rewriting logic, which is the only real logic here."""

from __future__ import annotations

import copy
import json

import pytest
import typer

from grafana_migrate import (
    DST_TOKEN_VARS,
    DST_URL_VARS,
    SRC_TOKEN_VARS,
    SRC_URL_VARS,
    Folder,
    GrafanaError,
    MapRow,
    Method,
    Resolver,
    annotation_key,
    build_datasource_map,
    index_by_folder_title,
    is_empty_after_drop,
    is_robot,
    is_unchanged,
    load_manifest,
    load_state,
    make_clients,
    mute_timings_in_tree,
    order_folders,
    prune_candidates,
    read_map_csv,
    receiver_of,
    receivers_in_tree,
    resolve_env,
    resolve_target,
    rewrite_alert_rule,
    rewrite_dashboard,
    rewrite_library_element,
    rule_is_unchanged,
    unchanged_rule_groups,
    write_map_csv,
)

SRC_DS = [
    {"uid": "src-prom", "name": "Prod Prometheus", "type": "prometheus"},
    {"uid": "shared-uid", "name": "Thanos", "type": "prometheus"},
    {"uid": "src-loki", "name": "Loki Prod", "type": "loki"},
    {"uid": "src-orphan", "name": "Decommissioned MSSQL", "type": "mssql"},
]
DST_DS = [
    {"uid": "dst-prom", "name": "Prod Prometheus", "type": "prometheus"},
    {"uid": "shared-uid", "name": "Thanos", "type": "prometheus"},
    {"uid": "dst-loki", "name": "loki prod", "type": "loki"},
]


@pytest.fixture
def resolver() -> Resolver:
    return Resolver(build_datasource_map(SRC_DS, DST_DS))


# --------------------------------------------------------------------------- #
# build_datasource_map
# --------------------------------------------------------------------------- #


def test_map_prefers_identical_uid_over_name():
    rows = {r.src_uid: r for r in build_datasource_map(SRC_DS, DST_DS)}
    assert rows["shared-uid"].dst_uid == "shared-uid"
    assert rows["shared-uid"].method == Method.UID


def test_map_falls_back_to_name_and_type():
    rows = {r.src_uid: r for r in build_datasource_map(SRC_DS, DST_DS)}
    assert rows["src-prom"].dst_uid == "dst-prom"
    assert rows["src-prom"].method == Method.NAME


def test_map_name_match_is_case_insensitive():
    rows = {r.src_uid: r for r in build_datasource_map(SRC_DS, DST_DS)}
    assert rows["src-loki"].dst_uid == "dst-loki"


def test_map_reports_unmatched_instead_of_guessing():
    rows = {r.src_uid: r for r in build_datasource_map(SRC_DS, DST_DS)}
    orphan = rows["src-orphan"]
    assert orphan.dst_uid == ""
    assert orphan.method == Method.UNRESOLVED
    assert not orphan.resolved


def test_map_csv_roundtrip_marks_hand_filled_rows_manual(tmp_path):
    path = tmp_path / "map.csv"
    write_map_csv(build_datasource_map(SRC_DS, DST_DS), path)
    text = path.read_text(encoding="utf-8").replace(
        "src-orphan,Decommissioned MSSQL,mssql,,,,UNRESOLVED",
        "src-orphan,Decommissioned MSSQL,mssql,dst-mssql,New MSSQL,mssql,UNRESOLVED",
    )
    path.write_text(text, encoding="utf-8")

    rows = {r.src_uid: r for r in read_map_csv(path)}
    assert rows["src-orphan"].dst_uid == "dst-mssql"
    assert rows["src-orphan"].method == Method.MANUAL
    assert rows["src-orphan"].resolved
    assert rows["src-prom"].method == Method.NAME


# --------------------------------------------------------------------------- #
# rewrite_dashboard
# --------------------------------------------------------------------------- #


def test_rewrites_modern_object_reference(resolver):
    dash = {"uid": "d1", "panels": [{"datasource": {"type": "prometheus", "uid": "src-prom"}}]}
    out, stats = rewrite_dashboard(dash, resolver)
    assert out["panels"][0]["datasource"] == {"type": "prometheus", "uid": "dst-prom"}
    assert stats.rewritten == 1
    assert stats.ok


def test_rewrites_legacy_string_reference_by_name(resolver):
    """Pre-v8 dashboards store the datasource *name* as a bare string."""
    dash = {"uid": "d1", "panels": [{"datasource": "Prod Prometheus"}]}
    out, stats = rewrite_dashboard(dash, resolver)
    assert out["panels"][0]["datasource"] == "dst-prom"
    assert stats.rewritten == 1


def test_rewrites_per_target_datasource(resolver):
    dash = {
        "uid": "d1",
        "panels": [
            {
                "datasource": {"type": "datasource", "uid": "-- Mixed --"},
                "targets": [
                    {"refId": "A", "datasource": {"type": "prometheus", "uid": "src-prom"}},
                    {"refId": "B", "datasource": {"type": "loki", "uid": "src-loki"}},
                ],
            }
        ],
    }
    out, stats = rewrite_dashboard(dash, resolver)
    uids = [t["datasource"]["uid"] for t in out["panels"][0]["targets"]]
    assert uids == ["dst-prom", "dst-loki"]
    assert stats.builtin_refs == 1


def test_rewrites_panels_nested_in_collapsed_rows(resolver):
    dash = {
        "uid": "d1",
        "panels": [
            {
                "type": "row",
                "collapsed": True,
                "panels": [{"datasource": {"type": "prometheus", "uid": "src-prom"}}],
            }
        ],
    }
    out, stats = rewrite_dashboard(dash, resolver)
    assert out["panels"][0]["panels"][0]["datasource"]["uid"] == "dst-prom"
    assert stats.rewritten == 1


def test_rewrites_annotations_and_datasource_uid_key(resolver):
    dash = {
        "uid": "d1",
        "annotations": {
            "list": [
                {"name": "deploys", "datasource": {"type": "loki", "uid": "src-loki"}},
                {"name": "alerts", "datasourceUid": "src-prom"},
            ]
        },
    }
    out, stats = rewrite_dashboard(dash, resolver)
    assert out["annotations"]["list"][0]["datasource"]["uid"] == "dst-loki"
    assert out["annotations"]["list"][1]["datasourceUid"] == "dst-prom"
    assert stats.rewritten == 2


def test_rewrites_selected_value_of_datasource_template_variable(resolver):
    dash = {
        "uid": "d1",
        "templating": {
            "list": [
                {
                    "type": "datasource",
                    "name": "ds",
                    "query": "prometheus",
                    "current": {"text": "Prod Prometheus", "value": "src-prom"},
                }
            ]
        },
    }
    out, stats = rewrite_dashboard(dash, resolver)
    assert out["templating"]["list"][0]["current"]["value"] == "dst-prom"
    assert out["templating"]["list"][0]["query"] == "prometheus", "plugin type must not be remapped"
    assert stats.rewritten == 1


def test_leaves_template_variable_references_alone(resolver):
    dash = {
        "uid": "d1",
        "panels": [
            {"datasource": {"type": "prometheus", "uid": "${ds}"}},
            {"datasource": "$ds"},
            {"datasource": {"type": "prometheus", "uid": "${ds:raw}"}},
        ],
    }
    out, stats = rewrite_dashboard(dash, resolver)
    assert out["panels"][0]["datasource"]["uid"] == "${ds}"
    assert out["panels"][1]["datasource"] == "$ds"
    assert stats.template_refs == 3
    assert stats.rewritten == 0


def test_leaves_builtin_datasources_alone(resolver):
    dash = {
        "uid": "d1",
        "panels": [
            {"datasource": {"type": "datasource", "uid": "grafana"}},
            {"datasource": "-- Dashboard --"},
            {"datasource": {"type": "__expr__", "uid": "__expr__"}},
        ],
    }
    out, stats = rewrite_dashboard(dash, resolver)
    assert out["panels"][0]["datasource"]["uid"] == "grafana"
    assert stats.builtin_refs == 3
    assert stats.ok


def test_counts_null_datasource_as_inheriting_the_target_default(resolver):
    """A null reference silently follows the *target* default, which differs."""
    dash = {"uid": "d1", "panels": [{"datasource": None}]}
    out, stats = rewrite_dashboard(dash, resolver)
    assert out["panels"][0]["datasource"] is None
    assert stats.inherited_default == 1


def test_counts_matching_uid_as_already_correct_not_rewritten(resolver):
    dash = {"uid": "d1", "panels": [{"datasource": {"type": "prometheus", "uid": "shared-uid"}}]}
    _, stats = rewrite_dashboard(dash, resolver)
    assert stats.already_correct == 1
    assert stats.rewritten == 0


def test_unresolved_reference_is_reported_and_left_untouched(resolver):
    dash = {"uid": "d1", "panels": [{"datasource": {"type": "mssql", "uid": "src-orphan"}}]}
    out, stats = rewrite_dashboard(dash, resolver)
    assert out["panels"][0]["datasource"]["uid"] == "src-orphan"
    assert not stats.ok
    assert "no target mapping" in stats.unresolved[0]


def test_reference_absent_from_the_source_is_dangling_not_blocking(resolver):
    """Real instances carry dashboards pointing at long-deleted datasources.

    Those are broken *today*; copying them as-is is not a regression, so they
    must not block the whole migration.
    """
    dash = {"uid": "d1", "panels": [{"datasource": {"type": "prometheus", "uid": "never-seen"}}]}
    out, stats = rewrite_dashboard(dash, resolver)
    assert stats.ok, "a dangling reference must not block"
    assert stats.unresolved == []
    assert "does not exist on the source" in stats.dangling[0]
    assert out["panels"][0]["datasource"]["uid"] == "never-seen"


def test_dangling_string_reference_is_also_detected(resolver):
    dash = {"uid": "d1", "panels": [{"datasource": "prometheus_central"}]}
    _, stats = rewrite_dashboard(dash, resolver)
    assert stats.ok
    assert len(stats.dangling) == 1


def test_source_datasource_without_target_still_blocks(resolver):
    """The datasource exists on the source, so losing it *is* a regression."""
    dash = {"uid": "d1", "panels": [{"datasource": {"type": "mssql", "uid": "src-orphan"}}]}
    _, stats = rewrite_dashboard(dash, resolver)
    assert not stats.ok
    assert stats.dangling == []


def test_unresolved_message_points_at_the_panel_path(resolver):
    dash = {
        "uid": "d1",
        "panels": [{}, {"targets": [{}, {"datasource": {"type": "mssql", "uid": "src-orphan"}}]}],
    }
    _, stats = rewrite_dashboard(dash, resolver)
    assert "panels[1].targets[1].datasource" in stats.unresolved[0]


def test_dangling_and_blocking_are_reported_separately(resolver):
    dash = {
        "uid": "d1",
        "panels": [
            {"datasource": {"type": "prometheus", "uid": "ghost"}},
            {"datasource": {"type": "mssql", "uid": "src-orphan"}},
            {"datasource": {"type": "prometheus", "uid": "src-prom"}},
        ],
    }
    _, stats = rewrite_dashboard(dash, resolver)
    assert len(stats.dangling) == 1
    assert len(stats.unresolved) == 1
    assert stats.rewritten == 1
    assert not stats.ok


def test_warns_on_library_panels(resolver):
    dash = {
        "uid": "d1",
        "panels": [{"title": "CPU", "libraryPanel": {"uid": "lp1", "name": "CPU"}}],
    }
    _, stats = rewrite_dashboard(dash, resolver)
    assert any("library panel" in w for w in stats.warnings)


def test_warns_on_legacy_panel_alerts(resolver):
    dash = {"uid": "d1", "panels": [{"title": "CPU", "alert": {"conditions": []}}]}
    _, stats = rewrite_dashboard(dash, resolver)
    assert any("legacy panel alert" in w for w in stats.warnings)


def test_preserves_uid_and_drops_instance_local_fields(resolver):
    dash = {"uid": "keep-me", "id": 42, "version": 7, "title": "T"}
    out, _ = rewrite_dashboard(dash, resolver)
    assert out["uid"] == "keep-me", "uid must survive: it keeps permalinks and makes reruns idempotent"
    assert out["id"] is None
    assert "version" not in out
    assert out["title"] == "T"


def test_does_not_mutate_the_source_dashboard(resolver):
    dash = {
        "uid": "d1",
        "id": 42,
        "panels": [{"datasource": {"type": "prometheus", "uid": "src-prom"}}],
        "templating": {"list": [{"type": "datasource", "current": {"value": "src-prom"}}]},
    }
    original = copy.deepcopy(dash)
    rewrite_dashboard(dash, resolver)
    assert dash == original


def test_is_deterministic(resolver):
    dash = {
        "uid": "d1",
        "panels": [
            {"datasource": {"type": "prometheus", "uid": "src-prom"}},
            {"datasource": "Loki Prod", "targets": [{"datasource": None}]},
        ],
    }
    first, _ = rewrite_dashboard(copy.deepcopy(dash), resolver)
    second, _ = rewrite_dashboard(copy.deepcopy(dash), resolver)
    assert first == second


# --------------------------------------------------------------------------- #
# Folder ordering
# --------------------------------------------------------------------------- #


def test_parents_are_created_before_their_children():
    folders = {
        "c": Folder("c", "child", "b"),
        "a": Folder("a", "root", None),
        "b": Folder("b", "mid", "a"),
    }
    order = [f.uid for f in order_folders(folders)]
    assert order.index("a") < order.index("b") < order.index("c")


def test_folder_with_parent_outside_the_selection_is_treated_as_a_root():
    folders = {"x": Folder("x", "orphan", "not-selected")}
    assert [f.uid for f in order_folders(folders)] == ["x"]


def test_folder_cycle_is_rejected_loudly():
    folders = {"a": Folder("a", "a", "b"), "b": Folder("b", "b", "a")}
    with pytest.raises(GrafanaError, match="cycle"):
        order_folders(folders)


def test_maprow_without_target_is_not_resolved():
    assert not MapRow("u", "n", "t", "", "", "", str(Method.UNRESOLVED)).resolved
    assert MapRow("u", "n", "t", "d", "n", "t", str(Method.UID)).resolved


# --------------------------------------------------------------------------- #
# Environment resolution
# --------------------------------------------------------------------------- #


@pytest.fixture
def clean_env(monkeypatch):
    for name in (*SRC_URL_VARS, *SRC_TOKEN_VARS, *DST_URL_VARS, *DST_TOKEN_VARS):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_explicit_src_vars_win_over_the_ambient_ones(clean_env):
    clean_env.setenv("SRC_URL", "https://explicit")
    clean_env.setenv("GRAFANA_URL", "https://ambient")
    assert resolve_env(SRC_URL_VARS) == ("SRC_URL", "https://explicit")


def test_source_falls_back_to_grafana_url(clean_env):
    clean_env.setenv("GRAFANA_URL", "https://grafana.example.com/")
    assert resolve_env(SRC_URL_VARS) == ("GRAFANA_URL", "https://grafana.example.com/")


def test_source_token_fallback_order(clean_env):
    clean_env.setenv("GRAFANA_SERVICE_ACCOUNT_TOKEN", "sa")
    assert resolve_env(SRC_TOKEN_VARS) == ("GRAFANA_SERVICE_ACCOUNT_TOKEN", "sa")
    clean_env.setenv("GRAFANA_TOKEN", "plain")
    assert resolve_env(SRC_TOKEN_VARS) == ("GRAFANA_TOKEN", "plain")
    clean_env.setenv("SRC_TOKEN", "explicit")
    assert resolve_env(SRC_TOKEN_VARS) == ("SRC_TOKEN", "explicit")


def test_blank_variable_is_treated_as_unset(clean_env):
    clean_env.setenv("SRC_URL", "   ")
    clean_env.setenv("GRAFANA_URL", "https://ambient")
    assert resolve_env(SRC_URL_VARS) == ("GRAFANA_URL", "https://ambient")


def test_target_never_reads_the_ambient_grafana_vars(clean_env):
    """An ambient GRAFANA_* must never be able to become a write target."""
    clean_env.setenv("GRAFANA_URL", "https://grafana.example.com/")
    clean_env.setenv("GRAFANA_TOKEN", "tok")
    assert resolve_env(DST_URL_VARS) is None
    assert resolve_env(DST_TOKEN_VARS) is None


def test_missing_target_url_aborts_instead_of_guessing(clean_env):
    """The write target is never defaulted, even when a token is at hand."""
    clean_env.setenv("DST_TOKEN", "dsttok")
    with pytest.raises(typer.Exit):
        resolve_target()


def test_target_url_comes_from_dst_url(clean_env):
    clean_env.setenv("DST_URL", "https://other.grafana.net")
    clean_env.setenv("DST_TOKEN", "dsttok")
    assert resolve_target() == ("https://other.grafana.net", "dsttok")


def test_missing_token_is_asked_for_on_a_terminal(clean_env):
    clean_env.setenv("DST_URL", "https://example.grafana.net")
    clean_env.setattr("sys.stdin.isatty", lambda: True)
    clean_env.setattr("grafana_migrate.typer.prompt", lambda *a, **k: "  typed-token  ")
    url, token = resolve_target()
    assert url == "https://example.grafana.net"
    assert token == "typed-token", "a pasted token often carries whitespace"


def test_prompt_hides_the_input(clean_env):
    """The token must not land in the scrollback or the shell history."""
    seen = {}

    def fake_prompt(*args, **kwargs):
        seen.update(kwargs)
        return "tok"

    clean_env.setenv("DST_URL", "https://example.grafana.net")
    clean_env.setattr("sys.stdin.isatty", lambda: True)
    clean_env.setattr("grafana_migrate.typer.prompt", fake_prompt)
    resolve_target()
    assert seen["hide_input"] is True


def test_empty_typed_token_is_rejected(clean_env):
    clean_env.setenv("DST_URL", "https://example.grafana.net")
    clean_env.setattr("sys.stdin.isatty", lambda: True)
    clean_env.setattr("grafana_migrate.typer.prompt", lambda *a, **k: "   ")
    with pytest.raises(typer.Exit):
        resolve_target()


def test_missing_token_without_a_terminal_exits_instead_of_hanging(clean_env):
    """In CI there is nobody to answer: fail fast rather than block the job."""
    clean_env.setenv("DST_URL", "https://example.grafana.net")
    clean_env.setattr("sys.stdin.isatty", lambda: False)
    with pytest.raises(typer.Exit):
        resolve_target()


def test_make_clients_uses_the_ambient_source_and_the_explicit_target(clean_env):
    clean_env.setenv("GRAFANA_URL", "https://grafana.example.com/")
    clean_env.setenv("GRAFANA_TOKEN", "tok")
    clean_env.setenv("DST_URL", "https://example.grafana.net")
    clean_env.setenv("DST_TOKEN", "dsttok")
    src, dst = make_clients()
    assert src.base_url == "https://grafana.example.com"
    assert dst.base_url == "https://example.grafana.net"


def test_make_clients_aborts_when_the_source_is_unresolvable(clean_env):
    clean_env.setenv("DST_TOKEN", "dsttok")
    with pytest.raises(typer.Exit):
        make_clients()


def test_stale_picker_selection_is_cleared_not_blocked(resolver):
    """A datasource variable's current.value is UI state, not a hard reference.

    Grafana repopulates it from the variable's own query on load, and the panels
    behind it point at ${var}. Blocking a whole dashboard on it would be wrong.
    """
    dash = {
        "uid": "d1",
        "templating": {
            "list": [
                {
                    "type": "datasource",
                    "name": "ds",
                    "query": "mssql",
                    "current": {"text": "Decommissioned MSSQL", "value": "src-orphan"},
                }
            ]
        },
        "panels": [{"datasource": {"type": "mssql", "uid": "${ds}"}}],
    }
    out, stats = rewrite_dashboard(dash, resolver)
    assert stats.ok, "picker state must not block the dashboard"
    assert out["templating"]["list"][0]["current"] == {"text": "", "value": ""}
    assert any("stale picker selection" in w for w in stats.warnings)


def test_resolvable_picker_selection_is_still_remapped(resolver):
    dash = {
        "uid": "d1",
        "templating": {
            "list": [
                {"type": "datasource", "current": {"text": "Prod Prometheus", "value": "src-prom"}}
            ]
        },
    }
    out, stats = rewrite_dashboard(dash, resolver)
    assert out["templating"]["list"][0]["current"]["value"] == "dst-prom"
    assert stats.rewritten == 1


def test_blocking_datasources_are_reported_by_uid(resolver):
    """Plan aggregates by datasource: one missing datasource blocks many dashboards."""
    dash = {
        "uid": "d1",
        "panels": [
            {"datasource": {"type": "mssql", "uid": "src-orphan"}},
            {"targets": [{"datasource": {"type": "mssql", "uid": "src-orphan"}}]},
            {"datasource": {"type": "prometheus", "uid": "ghost"}},
        ],
    }
    _, stats = rewrite_dashboard(dash, resolver)
    assert stats.blocking_uids == {"src-orphan"}, "dangling refs are not blockers"


# --------------------------------------------------------------------------- #
# Deliberately abandoned datasources
# --------------------------------------------------------------------------- #


@pytest.fixture
def dropping_resolver() -> Resolver:
    """A map where the orphaned datasource was declared abandoned."""
    rows = [
        r
        if r.src_uid != "src-orphan"
        else MapRow(r.src_uid, r.src_name, r.src_type, "", "", "", str(Method.DROPPED))
        for r in build_datasource_map(SRC_DS, DST_DS)
    ]
    return Resolver(rows)


def test_drop_sentinel_is_read_back_from_the_csv(tmp_path):
    path = tmp_path / "map.csv"
    write_map_csv(build_datasource_map(SRC_DS, DST_DS), path)
    text = path.read_text(encoding="utf-8").replace(
        "src-orphan,Decommissioned MSSQL,mssql,,,,UNRESOLVED",
        "src-orphan,Decommissioned MSSQL,mssql,DROP,,,UNRESOLVED",
    )
    path.write_text(text, encoding="utf-8")

    row = {r.src_uid: r for r in read_map_csv(path)}["src-orphan"]
    assert row.method == Method.DROPPED
    assert row.dropped
    assert not row.resolved, "a dropped datasource has no target"


def test_drop_sentinel_is_case_insensitive(tmp_path):
    path = tmp_path / "map.csv"
    write_map_csv(build_datasource_map(SRC_DS, DST_DS), path)
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "src-orphan,Decommissioned MSSQL,mssql,,,,UNRESOLVED",
            "src-orphan,Decommissioned MSSQL,mssql,drop,,,UNRESOLVED",
        ),
        encoding="utf-8",
    )
    assert {r.src_uid: r for r in read_map_csv(path)}["src-orphan"].dropped


def test_drop_survives_a_rewrite_of_the_map(tmp_path):
    """Rewriting the CSV must not silently lose the operator's decision."""
    path = tmp_path / "map.csv"
    rows = [MapRow("u", "n", "t", "", "", "", str(Method.DROPPED))]
    write_map_csv(rows, path)
    assert "DROP" in path.read_text(encoding="utf-8")
    assert read_map_csv(path)[0].dropped


def test_dropped_datasource_does_not_block_the_dashboard(dropping_resolver):
    dash = {
        "uid": "d1",
        "panels": [
            {"datasource": {"type": "mssql", "uid": "src-orphan"}},
            {"datasource": {"type": "prometheus", "uid": "src-prom"}},
        ],
    }
    out, stats = rewrite_dashboard(dash, dropping_resolver)
    assert stats.ok, "an abandoned datasource is a decision, not a blocker"
    assert stats.blocking_uids == set()
    assert len(stats.dropped) == 1
    assert stats.rewritten == 1
    assert out["panels"][0]["datasource"]["uid"] == "src-orphan", "left as-is on purpose"


def test_dropped_is_reported_separately_from_dangling(dropping_resolver):
    dash = {
        "uid": "d1",
        "panels": [
            {"datasource": {"type": "mssql", "uid": "src-orphan"}},
            {"datasource": {"type": "prometheus", "uid": "never-seen"}},
        ],
    }
    _, stats = rewrite_dashboard(dash, dropping_resolver)
    assert len(stats.dropped) == 1, "declared abandoned"
    assert len(stats.dangling) == 1, "absent from the source too"
    assert stats.ok


# --------------------------------------------------------------------------- #
# Alert rules
# --------------------------------------------------------------------------- #

RULE = {
    "id": 82,
    "uid": "rule-1",
    "orgID": 1,
    "updated": "2026-08-14T08:44:59Z",
    "folderUID": "f1",
    "ruleGroup": "1m",
    "title": "High CPU",
    "condition": "C",
    "isPaused": False,
    "for": "30m",
    "annotations": {
        "dashboard_url": "https://grafana.example.com/d/abc/firewall?viewPanel=37",
        "runbook_url": "https://wiki.example.com/runbooks/high-cpu",
        "summary": "cpu is high",
    },
    "labels": {"severity": "warning"},
    "notification_settings": {"receiver": "team-platform"},
    "data": [
        {
            "refId": "A",
            "datasourceUid": "src-prom",
            "model": {"datasource": {"type": "prometheus", "uid": "src-prom"}, "expr": "up"},
        },
        {
            "refId": "C",
            "datasourceUid": "__expr__",
            "model": {"datasource": {"type": "__expr__", "uid": "__expr__"}, "type": "threshold"},
        },
    ],
}


def test_rule_rewrites_both_datasource_uid_and_the_mirrored_model(resolver):
    """A rule carries the uid twice; missing the copy inside model breaks the query."""
    out, stats, _ = rewrite_alert_rule(RULE, resolver, "grafana.example.com", "example.grafana.net")
    assert out["data"][0]["datasourceUid"] == "dst-prom"
    assert out["data"][0]["model"]["datasource"]["uid"] == "dst-prom"
    assert stats.rewritten == 2


def test_rule_leaves_expression_queries_alone(resolver):
    out, stats, _ = rewrite_alert_rule(RULE, resolver, "grafana.example.com", "example.grafana.net")
    assert out["data"][1]["datasourceUid"] == "__expr__"
    assert out["data"][1]["model"]["datasource"]["uid"] == "__expr__"
    assert stats.builtin_refs == 2


def test_rule_is_always_pushed_paused(resolver):
    """A migrated alert must never start paging by itself."""
    out, _, _ = rewrite_alert_rule(RULE, resolver, "grafana.example.com", "example.grafana.net")
    assert out["isPaused"] is True


def test_rule_keeps_its_uid_and_drops_instance_local_fields(resolver):
    out, _, _ = rewrite_alert_rule(RULE, resolver, "grafana.example.com", "example.grafana.net")
    assert out["uid"] == "rule-1"
    for gone in ("id", "orgID", "updated", "provenance"):
        assert gone not in out
    assert out["folderUID"] == "f1"
    assert out["ruleGroup"] == "1m"


def test_annotation_links_are_repointed_to_the_new_host(resolver):
    """Dashboard uids are preserved, so only the host is wrong."""
    out, _, relinked = rewrite_alert_rule(RULE, resolver, "grafana.example.com", "example.grafana.net")
    assert out["annotations"]["dashboard_url"] == "https://example.grafana.net/d/abc/firewall?viewPanel=37"
    assert relinked == 1


def test_links_to_other_systems_are_left_alone(resolver):
    out, _, _ = rewrite_alert_rule(RULE, resolver, "grafana.example.com", "example.grafana.net")
    assert out["annotations"]["runbook_url"].startswith("https://wiki.example.com")


def test_rule_rewrite_does_not_mutate_the_source(resolver):
    original = copy.deepcopy(RULE)
    rewrite_alert_rule(RULE, resolver, "grafana.example.com", "example.grafana.net")
    assert original == RULE


def test_receiver_is_extracted_for_the_contact_point_precheck():
    assert receiver_of(RULE) == "team-platform"
    assert receiver_of({"notification_settings": {}}) is None
    assert receiver_of({}) is None, "rules routed by the policy tree have no receiver"


def test_rule_with_a_dropped_datasource_is_not_blocked(dropping_resolver):
    rule = {**RULE, "data": [{"refId": "A", "datasourceUid": "src-orphan", "model": {}}]}
    _, stats, _ = rewrite_alert_rule(rule, dropping_resolver, "a", "b")
    assert stats.ok


def test_dashboard_with_only_dropped_datasources_is_flagged_empty(dropping_resolver):
    dash = {"uid": "d1", "panels": [{"datasource": {"type": "mssql", "uid": "src-orphan"}}]}
    _, stats = rewrite_dashboard(dash, dropping_resolver)
    assert is_empty_after_drop(stats)


def test_dashboard_keeping_one_live_panel_is_not_empty(dropping_resolver):
    dash = {
        "uid": "d1",
        "panels": [
            {"datasource": {"type": "mssql", "uid": "src-orphan"}},
            {"datasource": {"type": "prometheus", "uid": "src-prom"}},
        ],
    }
    _, stats = rewrite_dashboard(dash, dropping_resolver)
    assert not is_empty_after_drop(stats)


def test_a_template_variable_counts_as_a_live_panel(dropping_resolver):
    """${ds} resolves at render time against whatever the target offers."""
    dash = {
        "uid": "d1",
        "panels": [
            {"datasource": {"type": "mssql", "uid": "src-orphan"}},
            {"datasource": {"type": "prometheus", "uid": "${ds}"}},
        ],
    }
    _, stats = rewrite_dashboard(dash, dropping_resolver)
    assert not is_empty_after_drop(stats)


def test_dashboard_with_no_dropped_datasource_is_never_empty(resolver):
    dash = {"uid": "d1", "panels": [{"datasource": {"type": "prometheus", "uid": "src-prom"}}]}
    _, stats = rewrite_dashboard(dash, resolver)
    assert not is_empty_after_drop(stats)


# --------------------------------------------------------------------------- #
# Notification routing
# --------------------------------------------------------------------------- #

TREE = {
    "receiver": "grafana-default-email",
    "group_by": ["grafana_folder", "alertname"],
    "routes": [
        {
            "receiver": "team-platform",
            "object_matchers": [["team", "=", "pe"]],
            "mute_time_intervals": ["Weekends"],
            "routes": [{"receiver": "team-infra-prod", "object_matchers": [["env", "=", "prod"]]}],
        },
        {"receiver": "#team-payments", "object_matchers": [["__contacts__", "=~", ".*payments.*"]]},
    ],
}


def test_receivers_are_collected_at_every_depth():
    """A receiver three levels down still has to exist before the tree is pushed."""
    assert receivers_in_tree(TREE) == {
        "grafana-default-email",
        "team-platform",
        "team-infra-prod",
        "#team-payments",
    }


def test_mute_timings_are_collected_from_nested_routes():
    assert mute_timings_in_tree(TREE) == {"Weekends"}


def test_empty_tree_references_nothing():
    assert receivers_in_tree({}) == set()
    assert mute_timings_in_tree({}) == set()


def test_route_without_a_receiver_is_ignored():
    """A route with no receiver inherits its parent's, so it adds no requirement."""
    tree = {"routes": [{"object_matchers": [["a", "=", "b"]], "routes": [{"receiver": "X"}]}]}
    assert receivers_in_tree(tree) == {"X"}


# --------------------------------------------------------------------------- #
# Dashboards already sitting on the target
# --------------------------------------------------------------------------- #

TARGET_HITS = [
    {"uid": "hand-made-1", "title": "MSA Traffic", "folderTitle": "1 - Global"},
    {"uid": "same-uid", "title": "Onlining", "folderTitle": "ARCHI"},
    {"uid": "root-1", "title": "Scratch", "folderTitle": None},
]


def test_target_index_is_keyed_on_folder_and_title():
    index = index_by_folder_title(TARGET_HITS)
    assert index[("1 - global", "msa traffic")] == "hand-made-1"


def test_target_index_ignores_case_and_surrounding_space():
    index = index_by_folder_title([{"uid": "u", "title": "  Mixed Case  ", "folderTitle": "DS "}])
    assert index[("ds", "mixed case")] == "u"


def test_dashboards_at_the_root_are_indexed_under_general():
    """A dashboard with no folder lives in General, which is what search reports."""
    assert index_by_folder_title(TARGET_HITS)[("general", "scratch")] == "root-1"


def test_same_title_in_another_folder_is_not_a_twin():
    """Titles repeat across folders on purpose; only folder+title is a collision."""
    index = index_by_folder_title(TARGET_HITS)
    assert ("cd", "msa traffic") not in index


def test_first_hit_wins_when_the_target_already_has_twins():
    index = index_by_folder_title(
        [
            {"uid": "first", "title": "Dup", "folderTitle": "F"},
            {"uid": "second", "title": "Dup", "folderTitle": "F"},
        ]
    )
    assert index[("f", "dup")] == "first"


# --------------------------------------------------------------------------- #
# Incremental reruns
# --------------------------------------------------------------------------- #


def test_same_version_means_unchanged():
    state = {"d1": {"version": 7, "updated": "2026-01-07T08:54:45Z"}}
    assert is_unchanged(state, "d1", 7)


def test_a_newer_version_is_not_unchanged():
    state = {"d1": {"version": 7}}
    assert not is_unchanged(state, "d1", 8)


def test_an_unknown_dashboard_is_never_unchanged():
    assert not is_unchanged({}, "d1", 7)


def test_a_missing_version_is_never_unchanged():
    """No version means no evidence: push rather than silently skip."""
    assert not is_unchanged({"d1": {"version": 7}}, "d1", None)


def test_a_corrupt_state_entry_is_ignored():
    assert not is_unchanged({"d1": "garbage"}, "d1", 7)


def test_missing_state_file_reads_as_empty(tmp_path):
    assert load_state(tmp_path / "nope.json") == {}


def test_unreadable_state_file_reads_as_empty(tmp_path):
    """A lost state file must cost a redundant push, never a crash."""
    path = tmp_path / "state.json"
    path.write_text("{not json", encoding="utf-8")
    assert load_state(path) == {}


def test_state_file_that_is_not_a_mapping_reads_as_empty(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    assert load_state(path) == {}


def test_state_roundtrip(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(
        json.dumps({"d1": {"version": 3, "updated": "2026-09-01T10:00:00Z", "title": "T"}}),
        encoding="utf-8",
    )
    state = load_state(path)
    assert is_unchanged(state, "d1", 3)
    assert not is_unchanged(state, "d1", 4)


# --------------------------------------------------------------------------- #
# Incremental reruns, alert rules
# --------------------------------------------------------------------------- #

T1 = "2026-08-14T08:44:59Z"
T2 = "2026-09-20T11:02:03Z"


def _rule(uid, group, updated, folder="f1"):
    return {"uid": uid, "folderUID": folder, "ruleGroup": group, "updated": updated}


def test_rule_at_the_recorded_timestamp_is_unchanged():
    assert rule_is_unchanged({"r1": {"updated": T1}}, _rule("r1", "g", T1))


def test_rule_saved_since_is_changed():
    assert not rule_is_unchanged({"r1": {"updated": T1}}, _rule("r1", "g", T2))


def test_rule_absent_from_the_state_is_changed():
    assert not rule_is_unchanged({}, _rule("r1", "g", T1))


def test_rule_without_a_timestamp_is_changed():
    """No evidence means push, never silently skip."""
    assert not rule_is_unchanged({"r1": {"updated": T1}}, _rule("r1", "g", None))


def test_a_group_is_frozen_only_when_every_rule_is_unchanged():
    state = {"r1": {"updated": T1}, "r2": {"updated": T1}}
    rules = [_rule("r1", "g", T1), _rule("r2", "g", T1)]
    assert unchanged_rule_groups(rules, state) == {("f1", "g")}


def test_one_edited_rule_pushes_its_whole_group():
    """Apply replaces the group, so holding back its siblings would delete them."""
    state = {"r1": {"updated": T1}, "r2": {"updated": T1}}
    rules = [_rule("r1", "g", T1), _rule("r2", "g", T2)]
    assert unchanged_rule_groups(rules, state) == set()


def test_groups_are_judged_independently():
    state = {"r1": {"updated": T1}, "r2": {"updated": T1}}
    rules = [_rule("r1", "quiet", T1), _rule("r2", "busy", T2)]
    assert unchanged_rule_groups(rules, state) == {("f1", "quiet")}


def test_same_group_name_in_two_folders_is_two_groups():
    state = {"r1": {"updated": T1}, "r2": {"updated": T1}}
    rules = [_rule("r1", "1m", T1, "fa"), _rule("r2", "1m", T2, "fb")]
    assert unchanged_rule_groups(rules, state) == {("fa", "1m")}


def test_nothing_is_frozen_without_a_state():
    rules = [_rule("r1", "g", T1), _rule("r2", "g", T1)]
    assert unchanged_rule_groups(rules, {}) == set()


# --------------------------------------------------------------------------- #
# Library panels
# --------------------------------------------------------------------------- #

ELEMENT = {
    "uid": "afnbsmu2qfpc0c",
    "name": "Usage by type/provisioning",
    "kind": 1,
    "type": "timeseries",
    "folderUid": "af7y7f5wqk1s0f",
    "version": 2,
    "id": 41,
    "orgId": 1,
    "meta": {"connectedDashboards": 1},
    "model": {
        "title": "Core Usage",
        "type": "timeseries",
        "datasource": {"type": "prometheus", "uid": "src-prom"},
        "targets": [{"refId": "A", "datasource": {"type": "prometheus", "uid": "src-prom"}}],
    },
}


def test_library_element_keeps_its_uid(resolver):
    """Dashboards reference a library panel by uid; a new uid breaks every one of them."""
    payload, _ = rewrite_library_element(ELEMENT, resolver)
    assert payload["uid"] == "afnbsmu2qfpc0c"


def test_library_element_model_is_rewritten(resolver):
    payload, stats = rewrite_library_element(ELEMENT, resolver)
    assert payload["model"]["datasource"]["uid"] == "dst-prom"
    assert payload["model"]["targets"][0]["datasource"]["uid"] == "dst-prom"
    assert stats.rewritten == 2


def test_library_element_payload_drops_instance_local_fields(resolver):
    payload, _ = rewrite_library_element(ELEMENT, resolver)
    assert set(payload) == {"uid", "name", "kind", "folderUid", "model"}
    assert "id" not in payload
    assert "version" not in payload, "the update call uses the target's version, not the source's"


def test_library_element_keeps_its_folder(resolver):
    payload, _ = rewrite_library_element(ELEMENT, resolver)
    assert payload["folderUid"] == "af7y7f5wqk1s0f"


def test_library_element_with_an_unmapped_datasource_is_blocked(resolver):
    element = {**ELEMENT, "model": {"datasource": {"type": "mssql", "uid": "src-orphan"}}}
    _, stats = rewrite_library_element(element, resolver)
    assert not stats.ok


def test_library_element_without_a_model_is_harmless(resolver):
    payload, stats = rewrite_library_element({"uid": "u", "name": "n"}, resolver)
    assert payload["model"] == {}
    assert stats.ok


# --------------------------------------------------------------------------- #
# Annotations
# --------------------------------------------------------------------------- #


def test_service_account_annotations_are_recognised():
    """4957 of 5000 on this instance are CI deployment markers, not notes."""
    assert is_robot({"login": "sa-1-ci-deploy-markers"})
    assert not is_robot({"login": "alice@example.com"})


def test_annotation_without_an_author_is_not_a_robot():
    assert not is_robot({})
    assert not is_robot({"login": None})


def test_annotation_identity_ignores_the_instance_local_id():
    a = {"id": 516633773, "dashboardUID": "d1", "panelId": 4, "time": 1790082726859, "text": "x"}
    b = {"id": 42, "dashboardUID": "d1", "panelId": 4, "time": 1790082726859, "text": "x"}
    assert annotation_key(a) == annotation_key(b)


def test_annotation_identity_separates_different_moments():
    a = {"dashboardUID": "d1", "panelId": 4, "time": 1, "text": "x"}
    b = {"dashboardUID": "d1", "panelId": 4, "time": 2, "text": "x"}
    assert annotation_key(a) != annotation_key(b)


def test_annotation_identity_tolerates_missing_fields():
    assert annotation_key({}) == ("", 0, 0, "")


def test_annotation_identity_trims_the_text():
    a = {"dashboardUID": "d", "panelId": 1, "time": 5, "text": " rebalance ew4 "}
    b = {"dashboardUID": "d", "panelId": 1, "time": 5, "text": "rebalance ew4"}
    assert annotation_key(a) == annotation_key(b), "whitespace must not create a duplicate"


# --------------------------------------------------------------------------- #
# Pruning
# --------------------------------------------------------------------------- #

MANIFEST = {"pushed-1": "A/one", "pushed-2": "A/two", "pushed-3": "B/three"}


def test_prunes_what_we_pushed_and_the_source_lost():
    """Gone from the source, still on the target, and we are the ones who put it there."""
    assert prune_candidates(MANIFEST, {"pushed-1"}, {"pushed-1", "pushed-2", "pushed-3"}) == [
        "pushed-2",
        "pushed-3",
    ]


def test_never_touches_a_dashboard_created_on_the_target():
    """A dashboard born on Grafana Cloud is in no manifest, so it cannot be selected."""
    target = {"pushed-1", "cloud-native-1", "cloud-native-2"}
    assert prune_candidates(MANIFEST, {"pushed-1"}, target) == []


def test_a_dashboard_still_on_the_source_is_kept():
    assert prune_candidates(MANIFEST, set(MANIFEST), set(MANIFEST)) == []


def test_a_dashboard_already_gone_from_the_target_is_not_selected():
    """Nothing to delete twice: a rerun after a successful prune finds nothing."""
    assert prune_candidates(MANIFEST, set(), {"pushed-1"}) == ["pushed-1"]


def test_an_empty_manifest_selects_nothing():
    assert prune_candidates({}, set(), {"a", "b", "c"}) == []


def test_manifest_prefers_state_then_plan(tmp_path):
    (tmp_path / "state.json").write_text(
        json.dumps({"u1": {"version": 2, "title": "From state"}}), encoding="utf-8"
    )
    (tmp_path / "plan.csv").write_text(
        "uid,title,folder,action\nu1,From plan,F,create\nu2,Only in plan,F,update\n",
        encoding="utf-8",
    )
    m = load_manifest(tmp_path)
    assert m["u1"] == "From state", "state.json wins over the plan report"
    assert "u2" in m, "the plan still contributes what state.json does not know"


def test_manifest_ignores_skipped_and_blocked_plan_rows(tmp_path):
    (tmp_path / "plan.csv").write_text(
        "uid,title,folder,action\n"
        "u1,pushed,F,create\nu2,skipped,F,skip\nu3,blocked,F,BLOCKED\nu4,dup,F,DUPLICATE\n",
        encoding="utf-8",
    )
    assert set(load_manifest(tmp_path)) == {"u1"}


def test_manifest_survives_a_corrupt_rollback_file(tmp_path):
    (tmp_path / "plan.csv").write_text("uid,title,folder,action\nu1,a,F,create\n", encoding="utf-8")
    (tmp_path / "rollback.json").write_text("{not json", encoding="utf-8")
    assert set(load_manifest(tmp_path)) == {"u1"}


def test_manifest_is_empty_without_any_file(tmp_path):
    assert load_manifest(tmp_path) == {}
