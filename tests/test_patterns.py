"""
Tests for edr_workbook_builder.patterns:
  - is_lolbin
  - check_commandline
  - check_row
  - max_severity
"""

import pandas as pd
import pytest

from edr_workbook_builder.patterns import (
    FORMULA_PFXS,
    LOLBINS,
    SuspiciousMatch,
    check_commandline,
    check_row,
    is_lolbin,
    max_severity,
)


# ---------------------------------------------------------------------------
# is_lolbin
# ---------------------------------------------------------------------------


class TestIsLolbin:
    def test_powershell_is_lolbin(self):
        assert is_lolbin("powershell") is True

    def test_rundll32_is_lolbin(self):
        assert is_lolbin("rundll32") is True

    def test_certutil_is_lolbin(self):
        assert is_lolbin("certutil") is True

    def test_case_insensitive(self):
        assert is_lolbin("PowerShell") is True
        assert is_lolbin("RUNDLL32") is True

    def test_notepad_not_lolbin(self):
        assert is_lolbin("notepad") is False

    def test_explorer_not_lolbin(self):
        assert is_lolbin("explorer") is False

    def test_empty_string_not_lolbin(self):
        assert is_lolbin("") is False

    def test_all_lolbins_are_lowercase(self):
        for name in LOLBINS:
            assert name == name.lower(), f"LOLBIN '{name}' is not lowercase"


# ---------------------------------------------------------------------------
# check_commandline
# ---------------------------------------------------------------------------


class TestCheckCommandline:
    def test_encoded_command_flag(self):
        m = check_commandline("powershell.exe -EncodedCommand JABhAD0AMQAyADMAIAA=")
        assert m is not None
        assert m.severity == 3
        assert "EncodedCommand" in m.reason

    def test_enc_abbreviation(self):
        m = check_commandline("powershell -Enc JABhAD0AMQAyADMAIAA=")
        assert m is not None
        assert m.severity == 3

    def test_short_base64_not_flagged(self):
        # Too short to be meaningful — should not flag
        m = check_commandline("cmd.exe /c echo aGVsbG8=")
        assert m is None

    def test_long_base64_blob(self):
        b64 = "A" * 80  # 80-char base64-like string
        m = check_commandline(f"cmd.exe /c {b64}")
        assert m is not None
        assert m.severity == 2

    def test_long_hex_blob(self):
        hex_blob = "a" * 100
        m = check_commandline(f"cmd.exe /c {hex_blob}")
        assert m is not None
        assert m.severity == 2

    def test_normal_commandline_not_flagged(self):
        m = check_commandline(r"C:\Windows\System32\cmd.exe /c whoami")
        assert m is None

    def test_empty_string_returns_none(self):
        assert check_commandline("") is None

    def test_nan_string_returns_none(self):
        assert check_commandline("nan") is None

    def test_none_returns_none(self):
        assert check_commandline(None) is None

    def test_encoded_command_takes_priority_over_base64(self):
        # A line with -EncodedCommand AND a long base64 blob should return severity 3
        long_b64 = "B" * 80
        cmd = f"powershell -Enc {long_b64}"
        m = check_commandline(cmd)
        assert m.severity == 3

    def test_case_insensitive_flag(self):
        m = check_commandline("powershell -encodedcommand JABhAD0AMQAyADMAIAA=")
        assert m is not None
        assert m.severity == 3


# ---------------------------------------------------------------------------
# check_row
# ---------------------------------------------------------------------------


class TestCheckRow:
    def test_lolbin_detected(self):
        row = pd.Series({
            "ImageFileName": r"C:\Windows\System32\powershell.exe",
            "CommandLine": "powershell.exe -NoProfile",
        })
        matches = check_row(row)
        assert any(m.severity == 1 and "LOLBin" in m.reason for m in matches)

    def test_encoded_command_detected(self):
        row = pd.Series({
            "ImageFileName": r"C:\Windows\System32\powershell.exe",
            "CommandLine": "powershell -Enc JABhAD0AMQAyADMAIAA=",
        })
        matches = check_row(row)
        assert any(m.severity == 3 for m in matches)

    def test_both_lolbin_and_encoded_returned(self):
        row = pd.Series({
            "ImageFileName": r"C:\Windows\System32\powershell.exe",
            "CommandLine": "powershell -EncodedCommand JABhAD0AMQAyADMAIAA=",
        })
        matches = check_row(row)
        severities = {m.severity for m in matches}
        assert 1 in severities   # LOLBin
        assert 3 in severities   # encoded command

    def test_sorted_by_descending_severity(self):
        row = pd.Series({
            "ImageFileName": r"C:\Windows\System32\powershell.exe",
            "CommandLine": "powershell -Enc JABhAD0AMQAyADMAIAA=",
        })
        matches = check_row(row)
        severities = [m.severity for m in matches]
        assert severities == sorted(severities, reverse=True)

    def test_clean_row_no_matches(self):
        row = pd.Series({
            "ImageFileName": r"C:\Windows\System32\notepad.exe",
            "CommandLine": "notepad.exe C:\\readme.txt",
        })
        assert check_row(row) == []

    def test_case_insensitive_column_match(self):
        row = pd.Series({
            "imagefilename": r"C:\Windows\System32\mshta.exe",
        })
        matches = check_row(row)
        assert any("LOLBin" in m.reason for m in matches)

    def test_process_exe_set_for_lolbin(self):
        row = pd.Series({"ImageFileName": r"C:\rundll32.exe"})
        matches = check_row(row)
        lolbin_matches = [m for m in matches if m.process_exe]
        assert lolbin_matches
        assert lolbin_matches[0].process_exe == "rundll32"

    def test_no_matching_columns_empty(self):
        row = pd.Series({"SomeOtherColumn": "value"})
        assert check_row(row) == []

    def test_empty_series_empty(self):
        assert check_row(pd.Series(dtype=object)) == []


# ---------------------------------------------------------------------------
# max_severity
# ---------------------------------------------------------------------------


class TestMaxSeverity:
    def test_empty_list_returns_zero(self):
        assert max_severity([]) == 0

    def test_single_match(self):
        m = SuspiciousMatch(reason="test", severity=2)
        assert max_severity([m]) == 2

    def test_multiple_returns_highest(self):
        matches = [
            SuspiciousMatch(reason="a", severity=1),
            SuspiciousMatch(reason="b", severity=3),
            SuspiciousMatch(reason="c", severity=2),
        ]
        assert max_severity(matches) == 3


# ---------------------------------------------------------------------------
# FORMULA_PFXS sanity check
# ---------------------------------------------------------------------------


class TestFormulaPfxs:
    def test_contains_expected_chars(self):
        for ch in "=+-@":
            assert ch in FORMULA_PFXS

    def test_normal_chars_not_in_pfxs(self):
        for ch in "abcABC0123":
            assert ch not in FORMULA_PFXS
