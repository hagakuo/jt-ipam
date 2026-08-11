"""Regression tests for periodic integration scheduler scope."""

from __future__ import annotations

import ast
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "jt-ipam-sync.py"


def _find_call(tree: ast.AST, dotted_name: str) -> ast.Call:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and ast.unparse(node.func) == dotted_name:
            return node
    raise AssertionError(f"call not found: {dotted_name}")


def _enclosing_for(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> ast.For:
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, ast.For):
            return current
    raise AssertionError("call is not enclosed by a for loop")


def test_integration_loops_share_the_database_session_scope() -> None:
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"), filename=str(SCRIPT))
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }

    loops = [
        _enclosing_for(_find_call(tree, name), parents)
        for name in (
            "esxi_svc.sync_instance",
            "wazuh_svc.sync_agents",
            "librenms_svc.sync_instance",
        )
    ]

    session_scope = parents[loops[0]]
    assert isinstance(session_scope, ast.AsyncWith)
    assert all(parents[loop] is session_scope for loop in loops)
