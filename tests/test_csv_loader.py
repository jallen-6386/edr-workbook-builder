from pathlib import Path

import pytest

from edr_workbook_builder.csv_loader import find_csv_files, load_csv


class TestFindCsvFiles:
    def test_finds_csv_files(self, tmp_path):
        (tmp_path / "a.csv").write_text("col\nval")
        (tmp_path / "b.csv").write_text("col\nval")
        (tmp_path / "readme.txt").write_text("ignore")
        files = find_csv_files(tmp_path)
        assert len(files) == 2
        assert all(f.suffix == ".csv" for f in files)

    def test_excludes_non_csv(self, tmp_path):
        (tmp_path / "data.csv").write_text("col\nval")
        (tmp_path / "notes.txt").write_text("notes")
        (tmp_path / "image.png").write_bytes(b"\x89PNG")
        files = find_csv_files(tmp_path)
        assert len(files) == 1

    def test_non_recursive_ignores_subfolders(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (tmp_path / "root.csv").write_text("col\nval")
        (sub / "nested.csv").write_text("col\nval")
        files = find_csv_files(tmp_path, recursive=False)
        assert len(files) == 1
        assert files[0].name == "root.csv"

    def test_recursive_finds_nested(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (tmp_path / "root.csv").write_text("col\nval")
        (sub / "nested.csv").write_text("col\nval")
        files = find_csv_files(tmp_path, recursive=True)
        assert len(files) == 2

    def test_returns_sorted(self, tmp_path):
        (tmp_path / "z.csv").write_text("col\nval")
        (tmp_path / "a.csv").write_text("col\nval")
        (tmp_path / "m.csv").write_text("col\nval")
        files = find_csv_files(tmp_path)
        assert files == sorted(files)

    def test_empty_folder(self, tmp_path):
        assert find_csv_files(tmp_path) == []


class TestLoadCsv:
    def test_valid_csv(self, tmp_path):
        f = tmp_path / "test.csv"
        f.write_text("ImageFileName,PID\npowershell.exe,1234\ncmd.exe,5678\n")
        result = load_csv(f)
        assert result.error is None
        assert result.dataframe is not None
        assert result.row_count == 2
        assert result.col_count == 2

    def test_header_only(self, tmp_path):
        f = tmp_path / "header.csv"
        f.write_text("Col1,Col2,Col3\n")
        result = load_csv(f)
        assert result.error is None
        assert result.row_count == 0
        assert result.col_count == 3

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.csv"
        f.write_text("")
        result = load_csv(f)
        # EmptyDataError — should be reported as an error, not a crash
        assert result.error is not None
        assert result.row_count == 0

    def test_utf8_bom_encoding(self, tmp_path):
        f = tmp_path / "bom.csv"
        f.write_bytes(b"\xef\xbb\xbfImageFileName,PID\npowershell.exe,1234\n")
        result = load_csv(f)
        assert result.error is None
        assert "ImageFileName" in result.dataframe.columns

    def test_values_preserved_as_strings(self, tmp_path):
        # PIDs and hashes should not be coerced to int/float
        f = tmp_path / "types.csv"
        f.write_text("PID,SHA256\n1234,abc123def456\n0,00000000\n")
        result = load_csv(f)
        assert result.error is None
        pids = result.dataframe["PID"].tolist()
        assert "1234" in pids  # must be string, not int

    def test_many_rows(self, tmp_path):
        lines = ["Col1,Col2"] + [f"val{i},{i}" for i in range(500)]
        f = tmp_path / "big.csv"
        f.write_text("\n".join(lines))
        result = load_csv(f)
        assert result.row_count == 500

    def test_windows1252_encoding(self, tmp_path):
        f = tmp_path / "win.csv"
        # Write a file with a Windows-1252 specific character (em dash = 0x97)
        f.write_bytes(b"Name,Value\nfoo\x97bar,1\n")
        result = load_csv(f)
        # Should load without error (falls back to windows-1252 or latin-1)
        assert result.error is None
