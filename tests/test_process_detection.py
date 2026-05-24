import pandas as pd
import pytest
from edr_workbook_builder.process_detection import detect_process_name, extract_exe_name


class TestExtractExeName:
    def test_windows_absolute_path(self):
        assert extract_exe_name(r"C:\Windows\System32\powershell.exe") == "powershell"

    def test_unix_absolute_path(self):
        assert extract_exe_name("/usr/bin/python3") == "python3"

    def test_bare_exe_name(self):
        assert extract_exe_name("cmd.exe") == "cmd"

    def test_unquoted_command_line_with_args(self):
        assert extract_exe_name(r"C:\Windows\System32\cmd.exe /c whoami") == "cmd"

    def test_quoted_path_with_args(self):
        assert extract_exe_name(r'"C:\Program Files\my app\tool.exe" --flag') == "tool"

    def test_quoted_path_no_args(self):
        assert extract_exe_name(r'"C:\Windows\notepad.exe"') == "notepad"

    def test_empty_string_returns_none(self):
        assert extract_exe_name("") is None

    def test_whitespace_only_returns_none(self):
        assert extract_exe_name("   ") is None

    def test_no_extension(self):
        assert extract_exe_name("/usr/bin/bash") == "bash"

    def test_encoded_powershell_command_line(self):
        # The exe stem should be extracted even with long encoded args
        result = extract_exe_name(r"powershell.exe -EncodedCommand JABhAD0AMQAyADMA")
        assert result == "powershell"

    def test_windows_no_directory(self):
        assert extract_exe_name("mshta.exe") == "mshta"


class TestDetectProcessName:
    def test_imagefilename_column(self):
        df = pd.DataFrame(
            {"ImageFileName": [r"C:\Windows\System32\powershell.exe"] * 5}
        )
        assert detect_process_name(df) == "powershell"

    def test_filename_column_fallback(self):
        df = pd.DataFrame({"FileName": [r"C:\Windows\System32\notepad.exe"] * 3})
        assert detect_process_name(df) == "notepad"

    def test_targetprocessname_column(self):
        df = pd.DataFrame({"TargetProcessName": ["/usr/bin/bash"] * 4})
        assert detect_process_name(df) == "bash"

    def test_commandline_column(self):
        df = pd.DataFrame(
            {"CommandLine": [r"C:\Windows\System32\cmd.exe /c echo hello"] * 3}
        )
        assert detect_process_name(df) == "cmd"

    def test_case_insensitive_column_match(self):
        df = pd.DataFrame({"imagefilename": [r"C:\Windows\notepad.exe"] * 2})
        assert detect_process_name(df) == "notepad"

    def test_no_matching_columns_returns_none(self):
        df = pd.DataFrame({"RandomColumn": ["value1", "value2"]})
        assert detect_process_name(df) is None

    def test_empty_dataframe_returns_none(self):
        assert detect_process_name(pd.DataFrame()) is None

    def test_all_null_column_returns_none(self):
        df = pd.DataFrame({"ImageFileName": [None, None, None]})
        assert detect_process_name(df) is None

    def test_priority_imagefilename_over_filename(self):
        # ImageFileName must win over FileName when both present
        df = pd.DataFrame(
            {
                "ImageFileName": [r"C:\Windows\powershell.exe"] * 3,
                "FileName": [r"C:\Windows\cmd.exe"] * 3,
            }
        )
        assert detect_process_name(df) == "powershell"

    def test_uses_mode_most_common_value(self):
        df = pd.DataFrame(
            {
                "ImageFileName": [
                    r"C:\Windows\powershell.exe",
                    r"C:\Windows\powershell.exe",
                    r"C:\Windows\powershell.exe",
                    r"C:\Windows\cmd.exe",
                ]
            }
        )
        assert detect_process_name(df) == "powershell"
