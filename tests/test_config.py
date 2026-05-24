"""
Tests for edr_workbook_builder.config:
  - load_config
  - apply_config_defaults
  - save_config
"""

import argparse
import configparser
from pathlib import Path

import pytest

from edr_workbook_builder.config import (
    BOOL_FLAGS,
    CONFIG_LOCAL_NAME,
    apply_config_defaults,
    load_config,
    save_config,
)


def _empty_args(**overrides):
    """Return a Namespace with all bool flags set to None (unset by user)."""
    ns = argparse.Namespace(**{f: None for f in BOOL_FLAGS})
    for k, v in overrides.items():
        setattr(ns, k, v)
    return ns


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------


class TestLoadConfig:
    def test_returns_configparser(self):
        cfg = load_config()
        assert isinstance(cfg, configparser.ConfigParser)

    def test_defaults_present(self):
        cfg = load_config()
        assert cfg.has_section("defaults")
        for flag in BOOL_FLAGS:
            assert cfg.has_option("defaults", flag)

    def test_all_defaults_are_false(self):
        cfg = load_config()
        for flag in BOOL_FLAGS:
            assert cfg.getboolean("defaults", flag) is False

    def test_extra_path_loaded(self, tmp_path):
        ini = tmp_path / "custom.ini"
        ini.write_text("[defaults]\nsummary = true\n")
        cfg = load_config(extra_path=ini)
        assert cfg.getboolean("defaults", "summary") is True

    def test_nonexistent_extra_path_ok(self, tmp_path):
        cfg = load_config(extra_path=tmp_path / "missing.ini")
        assert isinstance(cfg, configparser.ConfigParser)


# ---------------------------------------------------------------------------
# apply_config_defaults
# ---------------------------------------------------------------------------


class TestApplyConfigDefaults:
    def test_none_flag_filled_from_config_true(self):
        cfg = load_config()
        cfg.set("defaults", "summary", "true")
        args = _empty_args()
        apply_config_defaults(args, cfg)
        assert args.summary is True

    def test_none_flag_filled_from_config_false(self):
        cfg = load_config()
        args = _empty_args()
        apply_config_defaults(args, cfg)
        assert args.summary is False

    def test_explicit_true_not_overwritten(self):
        cfg = load_config()
        cfg.set("defaults", "summary", "false")
        args = _empty_args(summary=True)
        apply_config_defaults(args, cfg)
        assert args.summary is True

    def test_explicit_false_not_overwritten(self):
        cfg = load_config()
        cfg.set("defaults", "summary", "true")
        args = _empty_args(summary=False)
        apply_config_defaults(args, cfg)
        assert args.summary is False

    def test_all_flags_resolved_to_bool(self):
        cfg = load_config()
        args = _empty_args()
        apply_config_defaults(args, cfg)
        for flag in BOOL_FLAGS:
            val = getattr(args, flag)
            assert isinstance(val, bool), f"{flag} should be bool, got {type(val)}"


# ---------------------------------------------------------------------------
# save_config
# ---------------------------------------------------------------------------


class TestSaveConfig:
    def test_creates_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        args = _empty_args(summary=True, highlight=False)
        apply_config_defaults(args, load_config())
        saved = save_config(args, path=tmp_path / "out.ini")
        assert saved.exists()

    def test_round_trips_values(self, tmp_path):
        args = _empty_args()
        apply_config_defaults(args, load_config())
        args.summary = True
        args.highlight = True
        path = tmp_path / "cfg.ini"
        save_config(args, path=path)

        cfg2 = load_config(extra_path=path)
        assert cfg2.getboolean("defaults", "summary") is True
        assert cfg2.getboolean("defaults", "highlight") is True
        assert cfg2.getboolean("defaults", "timeline") is False

    def test_save_to_explicit_path(self, tmp_path):
        args = _empty_args()
        apply_config_defaults(args, load_config())
        custom = tmp_path / "custom.ini"
        result = save_config(args, path=custom)
        assert result == custom
        assert custom.exists()

    def test_all_bool_flags_written(self, tmp_path):
        args = _empty_args()
        apply_config_defaults(args, load_config())
        path = tmp_path / "full.ini"
        save_config(args, path=path)
        cfg = configparser.ConfigParser()
        cfg.read(path)
        for flag in BOOL_FLAGS:
            assert cfg.has_option("defaults", flag), f"Missing flag: {flag}"
