"""
Process tree reconstruction from EDR process-graph columns.

Reads ProcessId / ParentProcessId columns across all loaded CSVs, builds an
adjacency list, and renders a DFS tree with box-drawing characters into a
list of row dicts for the ProcessTree sheet.

Limits:
  MAX_NODES = 500 — caps total unique nodes to prevent runaway sheet sizes.
  Cycles are detected by tracking visited PIDs during DFS.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

import pandas as pd

logger = logging.getLogger(__name__)

MAX_NODES = 500

# Column names checked case-insensitively.
_PID_COLS  = ["processid", "pid"]
_PPID_COLS = ["parentprocessid", "ppid"]
_EXE_COLS  = ["imagefilename", "filename", "processname", "targetprocessname", "parentbasefilename"]
_CMD_COLS  = ["commandline"]

_BRANCH = "├─ "
_LAST   = "└─ "
_PIPE   = "│  "
_SPACE  = "   "


@dataclass
class _ProcNode:
    pid: str
    ppid: str
    exe: str
    cmdline: str
    sheet_name: str


def _find_col(cols_lower: dict[str, str], candidates: list[str]) -> Optional[str]:
    for c in candidates:
        if c in cols_lower:
            return cols_lower[c]
    return None


def _extract_exe_stem(exe: str) -> str:
    """Return the filename portion of an exe path (no directory prefix, no args)."""
    if not exe:
        return "(unknown)"
    s = exe.strip()
    if s.startswith('"'):
        end = s.find('"', 1)
        s = s[1:end] if end > 1 else s[1:]
    else:
        s = s.split()[0] if s.split() else s
    for sep in ("/", "\\"):
        if sep in s:
            s = s.rsplit(sep, 1)[-1]
    return s or exe


def collect_nodes(load_results: list, sheet_names: list[str]) -> list[_ProcNode]:
    """
    Extract unique process nodes from all loaded CSVs.

    De-duplicates by PID (first occurrence wins).  Stops after MAX_NODES.
    Silently skips CSVs that lack both ProcessId and ParentProcessId columns.
    """
    seen_pids: set[str] = set()
    nodes: list[_ProcNode] = []

    for result, sheet_name in zip(load_results, sheet_names):
        if result.error or result.dataframe is None:
            continue

        df = result.dataframe
        cols_lower = {c.lower(): c for c in df.columns}

        pid_col  = _find_col(cols_lower, _PID_COLS)
        ppid_col = _find_col(cols_lower, _PPID_COLS)
        if not pid_col or not ppid_col:
            continue

        exe_col = _find_col(cols_lower, _EXE_COLS)
        cmd_col = _find_col(cols_lower, _CMD_COLS)

        for _, row in df.iterrows():
            if len(nodes) >= MAX_NODES:
                logger.warning(
                    "Process tree: reached %d-node limit — remaining rows skipped",
                    MAX_NODES,
                )
                return nodes

            pid_raw  = str(row[pid_col]).strip()
            ppid_raw = str(row[ppid_col]).strip()

            if not pid_raw or pid_raw in ("nan", "None", ""):
                continue
            if pid_raw in seen_pids:
                continue

            seen_pids.add(pid_raw)

            exe = str(row[exe_col]).strip() if exe_col else ""
            cmd = str(row[cmd_col]).strip() if cmd_col else ""
            exe = "" if exe in ("nan", "None") else exe
            cmd = "" if cmd in ("nan", "None") else cmd

            nodes.append(_ProcNode(
                pid=pid_raw,
                ppid=ppid_raw if ppid_raw not in ("nan", "None", "") else "",
                exe=exe,
                cmdline=cmd,
                sheet_name=sheet_name,
            ))

    return nodes


def _build_adjacency(
    nodes: list[_ProcNode],
) -> tuple[dict[str, _ProcNode], dict[str, list[str]], set[str]]:
    """Return (pid→node, pid→children list, root pid set)."""
    pid_map:  dict[str, _ProcNode]   = {n.pid: n for n in nodes}
    children: dict[str, list[str]]   = {n.pid: [] for n in nodes}
    all_pids = set(pid_map)

    for node in nodes:
        if node.ppid and node.ppid in all_pids:
            children[node.ppid].append(node.pid)

    roots = {n.pid for n in nodes if not n.ppid or n.ppid not in all_pids}
    return pid_map, children, roots


def build_process_tree_rows(load_results: list, sheet_names: list[str]) -> list[dict]:
    """
    Build row dicts for the ProcessTree sheet using DFS traversal.

    Returns [] if no CSV contains both ProcessId and ParentProcessId columns.

    Each dict has keys: Process, PID, PPID, CommandLine, SourceSheet.
    The 'Process' column carries the tree-drawing prefix characters.
    """
    nodes = collect_nodes(load_results, sheet_names)
    if not nodes:
        return []

    pid_map, children, roots = _build_adjacency(nodes)

    rows: list[dict] = []
    visited: set[str] = set()

    def _dfs(pid: str, prefix: str, is_last: bool) -> None:
        if pid in visited:
            return
        visited.add(pid)

        node = pid_map[pid]
        connector = _LAST if is_last else _BRANCH
        exe_display = _extract_exe_stem(node.exe)

        rows.append({
            "Process":     prefix + connector + exe_display,
            "PID":         node.pid,
            "PPID":        node.ppid,
            "CommandLine": node.cmdline,
            "SourceSheet": node.sheet_name,
        })

        child_ids = sorted(children.get(pid, []))
        for i, child_pid in enumerate(child_ids):
            child_is_last = i == len(child_ids) - 1
            child_prefix = prefix + (_SPACE if is_last else _PIPE)
            _dfs(child_pid, child_prefix, child_is_last)

    for i, root_pid in enumerate(sorted(roots)):
        _dfs(root_pid, "", i == len(roots) - 1)

    # Safety net: include any nodes DFS missed (orphans from cycle detection).
    for node in nodes:
        if node.pid not in visited:
            rows.append({
                "Process":     _LAST + _extract_exe_stem(node.exe),
                "PID":         node.pid,
                "PPID":        node.ppid,
                "CommandLine": node.cmdline,
                "SourceSheet": node.sheet_name,
            })

    return rows
