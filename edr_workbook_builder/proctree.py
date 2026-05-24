"""
Process tree reconstruction from EDR process-graph columns.

Reads ProcessId / ParentProcessId columns across all loaded CSVs, builds an
adjacency list, and renders a DFS tree with box-drawing characters into a
list of row dicts for the ProcessTree sheet.

PID recycling: the same numeric PID can belong to different processes across
time windows or across different source sheets.  Each node therefore gets a
composite UID of "{sheet_name}:{pid}".  Parent-child links prefer same-sheet
matches; cross-sheet links are made only when no same-sheet parent exists.

Limits:
  MAX_NODES = 500 — caps total unique nodes to prevent runaway sheet sizes.
  Cycles are detected by tracking visited UIDs during DFS.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

MAX_NODES = 500

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
    uid: str          # "{sheet_name}:{pid}" — globally unique identifier
    pid: str          # raw PID value (for display)
    ppid: str         # raw PPID value (for display)
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

    De-duplicates by (pid, sheet_name) — the same PID on the same sheet is
    collapsed to one node (first occurrence wins), but the same PID appearing
    on a different sheet is kept as a separate node to handle PID recycling.
    Stops after MAX_NODES.
    """
    seen: set[tuple[str, str]] = set()   # (pid, sheet_name)
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

            key = (pid_raw, sheet_name)
            if key in seen:
                continue
            seen.add(key)

            exe = str(row[exe_col]).strip() if exe_col else ""
            cmd = str(row[cmd_col]).strip() if cmd_col else ""
            exe = "" if exe in ("nan", "None") else exe
            cmd = "" if cmd in ("nan", "None") else cmd

            nodes.append(_ProcNode(
                uid=f"{sheet_name}:{pid_raw}",
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
    """
    Return (uid→node, uid→children list, root uid set).

    Parent matching prefers same-sheet parents (avoids cross-sheet PID
    collisions).  Falls back to any sheet only when no same-sheet parent
    exists for the PPID.
    """
    uid_map: dict[str, _ProcNode] = {n.uid: n for n in nodes}
    children: dict[str, list[str]] = {n.uid: [] for n in nodes}

    # pid → list of uids that share that pid (across sheets).
    pid_to_uids: dict[str, list[str]] = {}
    for n in nodes:
        pid_to_uids.setdefault(n.pid, []).append(n.uid)

    roots: set[str] = set()

    for node in nodes:
        if not node.ppid:
            roots.add(node.uid)
            continue

        # Prefer a parent on the same sheet.
        same_sheet_uid = f"{node.sheet_name}:{node.ppid}"
        if same_sheet_uid in uid_map:
            children[same_sheet_uid].append(node.uid)
        elif node.ppid in pid_to_uids:
            # Take the first cross-sheet candidate.
            children[pid_to_uids[node.ppid][0]].append(node.uid)
        else:
            roots.add(node.uid)

    return uid_map, children, roots


def build_process_tree_rows(load_results: list, sheet_names: list[str]) -> list[dict]:
    """
    Build row dicts for the ProcessTree sheet using DFS traversal.

    Returns [] if no CSV contains both ProcessId and ParentProcessId columns.

    Each dict has keys: Process, PID, PPID, CommandLine, SourceSheet.
    The 'Process' column carries tree-drawing prefix characters.
    """
    nodes = collect_nodes(load_results, sheet_names)
    if not nodes:
        return []

    uid_map, children, roots = _build_adjacency(nodes)

    rows: list[dict] = []
    visited: set[str] = set()

    def _dfs(uid: str, prefix: str, is_last: bool) -> None:
        if uid in visited:
            return
        visited.add(uid)

        node = uid_map[uid]
        connector  = _LAST if is_last else _BRANCH
        exe_display = _extract_exe_stem(node.exe)

        rows.append({
            "Process":     prefix + connector + exe_display,
            "PID":         node.pid,
            "PPID":        node.ppid,
            "CommandLine": node.cmdline,
            "SourceSheet": node.sheet_name,
        })

        child_uids = sorted(children.get(uid, []))
        for i, child_uid in enumerate(child_uids):
            child_is_last = i == len(child_uids) - 1
            child_prefix  = prefix + (_SPACE if is_last else _PIPE)
            _dfs(child_uid, child_prefix, child_is_last)

    sorted_roots = sorted(roots)
    for i, root_uid in enumerate(sorted_roots):
        _dfs(root_uid, "", i == len(sorted_roots) - 1)

    # Safety net: any nodes missed by DFS (shouldn't happen, but belt-and-braces).
    for node in nodes:
        if node.uid not in visited:
            rows.append({
                "Process":     _LAST + _extract_exe_stem(node.exe),
                "PID":         node.pid,
                "PPID":        node.ppid,
                "CommandLine": node.cmdline,
                "SourceSheet": node.sheet_name,
            })

    return rows
