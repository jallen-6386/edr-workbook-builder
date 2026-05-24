import pytest
from edr_workbook_builder.sheet_names import make_unique_sheet_names, sanitize_sheet_name


class TestSanitizeSheetName:
    def test_removes_brackets(self):
        assert sanitize_sheet_name("data[0]") == "data_0_"

    def test_removes_colon(self):
        assert sanitize_sheet_name("proc:name") == "proc_name"

    def test_removes_asterisk_and_question(self):
        assert sanitize_sheet_name("foo*bar?baz") == "foo_bar_baz"

    def test_removes_forward_slash(self):
        assert sanitize_sheet_name("path/name") == "path_name"

    def test_removes_backslash(self):
        assert sanitize_sheet_name("path\\name") == "path_name"

    def test_truncates_to_31(self):
        result = sanitize_sheet_name("a" * 40)
        assert len(result) == 31

    def test_empty_string_returns_sheet(self):
        assert sanitize_sheet_name("") == "Sheet"

    def test_strips_surrounding_whitespace(self):
        assert sanitize_sheet_name("  powershell  ") == "powershell"

    def test_preserves_valid_chars(self):
        assert sanitize_sheet_name("cmd_v2-beta") == "cmd_v2-beta"

    def test_exactly_31_chars_unchanged(self):
        name = "a" * 31
        assert sanitize_sheet_name(name) == name


class TestMakeUniqueSheetNames:
    def test_no_duplicates_unchanged(self):
        names = ["powershell", "cmd", "python"]
        assert make_unique_sheet_names(names) == ["powershell", "cmd", "python"]

    def test_duplicate_gets_counter_suffix(self):
        result = make_unique_sheet_names(["powershell", "powershell"])
        assert result[0] == "powershell"
        assert result[1] == "powershell_2"

    def test_triple_duplicate(self):
        result = make_unique_sheet_names(["powershell"] * 3)
        assert result == ["powershell", "powershell_2", "powershell_3"]

    def test_all_unique_after_dedup(self):
        result = make_unique_sheet_names(["powershell"] * 5)
        assert len(set(result)) == 5

    def test_all_within_31_chars(self):
        result = make_unique_sheet_names(["a" * 35] * 3)
        assert all(len(n) <= 31 for n in result)

    def test_case_insensitive_dedup(self):
        result = make_unique_sheet_names(["PowerShell", "powershell"])
        lower = [n.lower() for n in result]
        assert len(set(lower)) == 2

    def test_empty_list(self):
        assert make_unique_sheet_names([]) == []

    def test_existing_suffix_conflict_resolved(self):
        # "powershell_2" already taken; a second "powershell" duplicate should skip to _3
        result = make_unique_sheet_names(["powershell", "powershell_2", "powershell"])
        assert len(set(r.lower() for r in result)) == 3

    def test_invalid_chars_sanitized(self):
        result = make_unique_sheet_names(["proc[1]", "proc[2]"])
        assert all("[" not in n and "]" not in n for n in result)
