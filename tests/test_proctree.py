"""
Tests for edr_workbook_builder.proctree:
  - collect_nodes
  - _build_adjacency
  - build_process_tree_rows
"""

from pathlib import Path
from unittest.mock import MagicMock

import pandas as pd
import pytest

from edr_workbook_builder.proctree import (
    MAX_NODES,
    _build_adjacency,
    _extract_exe_stem,
    build_process_tree_rows,
    collect_nodes,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_result(df, name="test.csv", error=None):
    r = MagicMock()
    r.dataframe = df
    r.error = error
    r.path = Path(name)
    return r


def _proc_df(**rows):
    """Build a minimal process DataFrame from keyword args mapping col→list."""
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# _extract_exe_stem
# ---------------------------------------------------------------------------


class TestExtractExeStem:
    def test_full_path(self):
        assert _extract_exe_stem(r"C:\Windows\System32\cmd.exe") == "cmd.exe"

    def test_unix_path(self):
        assert _extract_exe_stem("/usr/bin/python3") == "python3"

    def test_empty(self):
        assert _extract_exe_stem("") == "(unknown)"

    def test_bare_name(self):
        assert _extract_exe_stem("powershell.exe") == "powershell.exe"

    def test_with_args(self):
        assert _extract_exe_stem("cmd.exe /c whoami") == "cmd.exe"

    def test_quoted_path(self):
        assert _extract_exe_stem('"C:\\Program Files\\app.exe" --flag') == "app.exe"


# ---------------------------------------------------------------------------
# collect_nodes
# ---------------------------------------------------------------------------


class TestCollectNodes:
    def test_basic_collection(self):
        df = _proc_df(
            ProcessId=["100", "200"],
            ParentProcessId=["0", "100"],
            ImageFileName=["explorer.exe", "cmd.exe"],
        )
        r = _make_result(df)
        nodes = collect_nodes([r], ["sheet1"])
        assert len(nodes) == 2
        pids = {n.pid for n in nodes}
        assert {"100", "200"} == pids

    def test_skips_missing_pid_ppid_cols(self):
        df = _proc_df(SomeCol=["value"])
        r = _make_result(df)
        nodes = collect_nodes([r], ["sheet1"])
        assert nodes == []

    def test_deduplicates_by_pid(self):
        df = _proc_df(
            ProcessId=["100", "100"],
            ParentProcessId=["0", "0"],
            ImageFileName=["cmd.exe", "cmd.exe"],
        )
        r = _make_result(df)
        nodes = collect_nodes([r], ["sheet1"])
        assert len(nodes) == 1

    def test_skips_errored_results(self):
        r = _make_result(None, error="parse error")
        assert collect_nodes([r], ["sheet1"]) == []

    def test_skips_nan_pid(self):
        df = _proc_df(
            ProcessId=["nan", "200"],
            ParentProcessId=["0", "100"],
        )
        r = _make_result(df)
        nodes = collect_nodes([r], ["sheet1"])
        assert len(nodes) == 1
        assert nodes[0].pid == "200"

    def test_captures_exe_and_cmdline(self):
        df = _proc_df(
            ProcessId=["100"],
            ParentProcessId=["0"],
            ImageFileName=["powershell.exe"],
            CommandLine=["-enc foo"],
        )
        r = _make_result(df)
        nodes = collect_nodes([r], ["sheet1"])
        assert nodes[0].exe == "powershell.exe"
        assert nodes[0].cmdline == "-enc foo"

    def test_case_insensitive_columns(self):
        df = pd.DataFrame({
            "processid":      ["100"],
            "parentprocessid": ["0"],
        })
        r = _make_result(df)
        nodes = collect_nodes([r], ["sheet1"])
        assert len(nodes) == 1


# ---------------------------------------------------------------------------
# _build_adjacency
# ---------------------------------------------------------------------------


class TestBuildAdjacency:
    def _nodes(self, data, sheet="s"):
        from edr_workbook_builder.proctree import _ProcNode
        return [
            _ProcNode(uid=f"{sheet}:{p}", pid=p, ppid=pp, exe=e, cmdline="", sheet_name=sheet)
            for p, pp, e in data
        ]

    def test_parent_child_link(self):
        nodes = self._nodes([("100", "0", "explorer.exe"), ("200", "100", "cmd.exe")])
        uid_map, children, roots = _build_adjacency(nodes)
        assert "s:200" in children["s:100"]
        assert "s:100" in roots

    def test_root_has_no_parent_in_set(self):
        nodes = self._nodes([("100", "0", "a.exe"), ("200", "100", "b.exe")])
        _, _, roots = _build_adjacency(nodes)
        assert roots == {"s:100"}

    def test_multiple_roots(self):
        nodes = self._nodes([("1", "", "a.exe"), ("2", "", "b.exe")])
        _, _, roots = _build_adjacency(nodes)
        assert roots == {"s:1", "s:2"}


# ---------------------------------------------------------------------------
# build_process_tree_rows
# ---------------------------------------------------------------------------


class TestBuildProcessTreeRows:
    def _result(self, pid_list, ppid_list, exe_list=None, name="s1"):
        data = {"ProcessId": pid_list, "ParentProcessId": ppid_list}
        if exe_list:
            data["ImageFileName"] = exe_list
        return _make_result(_proc_df(**data), name)

    def test_basic_tree_order(self):
        r = self._result(["1", "2", "3"], ["0", "1", "1"], ["a.exe", "b.exe", "c.exe"])
        rows = build_process_tree_rows([r], ["s1"])
        processes = [row["Process"] for row in rows]
        # Root (a.exe) should come first
        assert "a.exe" in processes[0]
        # Children should appear after root
        child_procs = processes[1:]
        assert any("b.exe" in p for p in child_procs)
        assert any("c.exe" in p for p in child_procs)

    def test_no_pid_ppid_cols_returns_empty(self):
        df = _proc_df(SomeCol=["value"])
        r = _make_result(df)
        assert build_process_tree_rows([r], ["s1"]) == []

    def test_source_sheet_populated(self):
        r = self._result(["100"], ["0"], ["cmd.exe"], "mysheet")
        rows = build_process_tree_rows([r], ["mysheet"])
        assert rows[0]["SourceSheet"] == "mysheet"

    def test_pid_ppid_present_in_output(self):
        r = self._result(["100", "200"], ["0", "100"], ["a.exe", "b.exe"])
        rows = build_process_tree_rows([r], ["s1"])
        pids = {row["PID"] for row in rows}
        assert {"100", "200"} == pids

    def test_tree_chars_in_process_column(self):
        r = self._result(["1", "2"], ["0", "1"], ["root.exe", "child.exe"])
        rows = build_process_tree_rows([r], ["s1"])
        # At least one non-root row should have tree-drawing characters
        non_root = [row["Process"] for row in rows if "root.exe" not in row["Process"]]
        assert any(("├─" in p or "└─" in p) for p in non_root)

    def test_all_rows_have_required_keys(self):
        r = self._result(["1"], ["0"], ["cmd.exe"])
        rows = build_process_tree_rows([r], ["s1"])
        for row in rows:
            assert set(row.keys()) == {"Process", "PID", "PPID", "CommandLine", "SourceSheet"}

    def test_multiple_sheets_merged(self):
        r1 = self._result(["1"], ["0"], ["a.exe"], "s1")
        r2 = self._result(["2"], ["1"], ["b.exe"], "s2")
        rows = build_process_tree_rows([r1, r2], ["s1", "s2"])
        pids = {row["PID"] for row in rows}
        assert {"1", "2"} == pids

    def test_pid_recycling_kept_separate(self):
        # PID 100 appears on two different sheets with different processes.
        # Both should appear as separate nodes in the tree output.
        r1 = self._result(["100"], ["0"], ["explorer.exe"], "s1")
        r2 = self._result(["100"], ["0"], ["svchost.exe"],  "s2")
        rows = build_process_tree_rows([r1, r2], ["s1", "s2"])
        # Two distinct nodes with PID=100 from different sheets.
        pid_100_rows = [row for row in rows if row["PID"] == "100"]
        assert len(pid_100_rows) == 2
        sources = {row["SourceSheet"] for row in pid_100_rows}
        assert sources == {"s1", "s2"}

    def test_same_pid_same_sheet_deduped(self):
        # The same PID appearing twice on the same sheet is collapsed.
        r = self._result(["100", "100"], ["0", "0"], ["cmd.exe", "cmd.exe"])
        rows = build_process_tree_rows([r], ["s1"])
        pid_100_rows = [row for row in rows if row["PID"] == "100"]
        assert len(pid_100_rows) == 1
