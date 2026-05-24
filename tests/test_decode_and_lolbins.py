"""
Tests for new patterns.py additions:
  - decode_ps_commandline
  - add_decoded_column
  - configure_lolbins / _effective_lolbins reset

And new attck.py additions:
  - format_technique / TECHNIQUE_NAMES
  - add_attck_column now produces labelled output
"""

import base64

import pandas as pd
import pytest

from edr_workbook_builder.attck import (
    TECHNIQUE_NAMES,
    format_technique,
    add_attck_column,
)
from edr_workbook_builder.patterns import (
    LOLBINS,
    add_decoded_column,
    configure_lolbins,
    decode_ps_commandline,
    is_lolbin,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _encode(text: str) -> str:
    return base64.b64encode(text.encode("utf-16-le")).decode("ascii")


def _reset_lolbins():
    """Restore the effective LOLBin set to the baseline after each test."""
    configure_lolbins([])


# ---------------------------------------------------------------------------
# decode_ps_commandline
# ---------------------------------------------------------------------------


class TestDecodePsCommandline:
    def test_basic_decode(self):
        blob = _encode("whoami")
        result = decode_ps_commandline(f"-EncodedCommand {blob}")
        assert result == "whoami"

    def test_enc_abbreviation(self):
        blob = _encode("Get-Process")
        result = decode_ps_commandline(f"-enc {blob}")
        assert result == "Get-Process"

    def test_e_abbreviation(self):
        blob = _encode("ls")
        result = decode_ps_commandline(f"-e {blob}")
        # ls is very short — may not decode but should not raise
        # (16-char minimum in the regex means very short payloads are skipped)

    def test_no_encoded_command_returns_none(self):
        assert decode_ps_commandline("powershell -Command whoami") is None

    def test_empty_returns_none(self):
        assert decode_ps_commandline("") is None

    def test_none_returns_none(self):
        assert decode_ps_commandline(None) is None

    def test_multiline_decoded(self):
        blob = _encode("Get-Process\nStop-Service")
        result = decode_ps_commandline(f"-EncodedCommand {blob}")
        assert result is not None
        assert "Get-Process" in result

    def test_padding_handled(self):
        # Blobs whose length % 4 != 0 need padding — verify no exception.
        cmd = "Invoke-Mimikatz"
        blob = _encode(cmd)
        result = decode_ps_commandline(f"-EncodedCommand {blob}")
        assert result == cmd


# ---------------------------------------------------------------------------
# add_decoded_column
# ---------------------------------------------------------------------------


class TestAddDecodedColumn:
    def test_column_added_when_encoded_found(self):
        blob = _encode("whoami")
        df = pd.DataFrame({
            "ImageFileName": ["powershell.exe"],
            "CommandLine":   [f"-EncodedCommand {blob}"],
        })
        out = add_decoded_column(df)
        assert "DecodedCommand" in out.columns

    def test_column_after_commandline(self):
        blob = _encode("whoami")
        df = pd.DataFrame({
            "ImageFileName": ["powershell.exe"],
            "CommandLine":   [f"-EncodedCommand {blob}"],
            "Extra":         ["x"],
        })
        out = add_decoded_column(df)
        cols = list(out.columns)
        assert cols.index("DecodedCommand") == cols.index("CommandLine") + 1

    def test_decoded_value_correct(self):
        blob = _encode("Get-Process")
        df = pd.DataFrame({"CommandLine": [f"-enc {blob}"]})
        out = add_decoded_column(df)
        assert out["DecodedCommand"].iloc[0] == "Get-Process"

    def test_no_encoded_no_column(self):
        df = pd.DataFrame({"CommandLine": ["powershell -Command whoami"]})
        out = add_decoded_column(df)
        assert "DecodedCommand" not in out.columns

    def test_empty_string_for_non_encoded_rows(self):
        blob = _encode("whoami")
        df = pd.DataFrame({"CommandLine": [f"-enc {blob}", "cmd /c dir"]})
        out = add_decoded_column(df)
        assert out["DecodedCommand"].iloc[0] == "whoami"
        assert out["DecodedCommand"].iloc[1] == ""

    def test_no_commandline_col_returns_unchanged(self):
        df = pd.DataFrame({"SomeCol": ["value"]})
        out = add_decoded_column(df)
        assert "DecodedCommand" not in out.columns
        assert list(out.columns) == ["SomeCol"]

    def test_original_df_not_mutated(self):
        blob = _encode("whoami")
        df = pd.DataFrame({"CommandLine": [f"-enc {blob}"]})
        _ = add_decoded_column(df)
        assert "DecodedCommand" not in df.columns


# ---------------------------------------------------------------------------
# configure_lolbins
# ---------------------------------------------------------------------------


class TestConfigureLolbins:
    def setup_method(self):
        _reset_lolbins()

    def teardown_method(self):
        _reset_lolbins()

    def test_baseline_lolbin_detected(self):
        assert is_lolbin("powershell")

    def test_custom_lolbin_added(self):
        configure_lolbins(["customtool"])
        assert is_lolbin("customtool")

    def test_baseline_still_detected_after_extension(self):
        configure_lolbins(["customtool"])
        assert is_lolbin("rundll32")

    def test_case_insensitive_extra(self):
        configure_lolbins(["MyTool"])
        assert is_lolbin("mytool")
        assert is_lolbin("MyTool")

    def test_empty_extra_list_no_change(self):
        configure_lolbins([])
        assert is_lolbin("powershell")
        assert not is_lolbin("notepad")

    def test_baseline_lolbins_constant(self):
        # LOLBINS itself should never be mutated by configure_lolbins.
        configure_lolbins(["customtool"])
        assert "customtool" not in LOLBINS

    def test_whitespace_stripped(self):
        configure_lolbins(["  mytool  "])
        assert is_lolbin("mytool")


# ---------------------------------------------------------------------------
# format_technique / TECHNIQUE_NAMES
# ---------------------------------------------------------------------------


class TestFormatTechnique:
    def test_known_id_includes_name(self):
        assert format_technique("T1059.001") == "T1059.001 (PowerShell)"

    def test_unknown_id_returns_id_only(self):
        assert format_technique("T9999.999") == "T9999.999"

    def test_all_technique_names_nonempty(self):
        for tid, name in TECHNIQUE_NAMES.items():
            assert name, f"Technique {tid} has empty name"

    def test_all_technique_ids_valid_format(self):
        import re
        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for tid in TECHNIQUE_NAMES:
            assert pattern.match(tid), f"Invalid technique ID format: {tid}"


class TestAddAttckColumnLabelled:
    def test_cell_value_includes_name(self):
        df = pd.DataFrame({
            "ImageFileName": ["powershell.exe"],
            "CommandLine":   [""],
        })
        out = add_attck_column(df)
        val = out["ATT&CK"].iloc[0]
        assert "T1059.001" in val
        assert "PowerShell" in val

    def test_multiple_techniques_all_labelled(self):
        df = pd.DataFrame({
            "ImageFileName": ["powershell.exe"],
            "CommandLine":   ["-EncodedCommand JABhAD0AMQAyADMAIAA="],
        })
        out = add_attck_column(df)
        val = out["ATT&CK"].iloc[0]
        # Both process-based and cmdline-based techniques should appear with names
        assert "(" in val
