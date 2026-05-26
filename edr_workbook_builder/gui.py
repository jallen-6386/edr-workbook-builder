"""
Tkinter GUI for EDR Workbook Builder.

Exposes the full set of CLI options in a graphical form. The workbook
build runs in a background thread so the UI stays responsive; log output
streams into the log pane in real time via a thread-safe queue.

Launch via:
  edr-workbook-builder --gui
  python -m edr_workbook_builder --gui
"""

import logging
import queue
import subprocess
import sys
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Optional


class _QueueHandler(logging.Handler):
    def __init__(self, q: queue.Queue) -> None:
        super().__init__()
        self.q = q

    def emit(self, record: logging.LogRecord) -> None:
        self.q.put(record)


class App(tk.Tk):
    _PAD = 6
    _LOG_TAG_COLORS = {
        logging.ERROR:   "#FF6B6B",
        logging.WARNING: "#FFD93D",
        logging.INFO:    "#D4D4D4",
        logging.DEBUG:   "#808080",
    }

    def __init__(self) -> None:
        super().__init__()
        self.title("EDR Workbook Builder")
        self.minsize(740, 640)
        self.resizable(True, True)

        self._log_queue: queue.Queue = queue.Queue()
        self._input_folders: list[str] = []
        self._running = False
        self._last_output: Optional[Path] = None

        self._build_ui()
        self._poll_log_queue()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=0)
        self.rowconfigure(1, weight=1)

        top = ttk.Frame(self, padding=self._PAD)
        top.grid(row=0, column=0, sticky="nsew")
        top.columnconfigure(0, weight=1)

        self._build_io(top)
        self._build_flags(top)
        self._build_advanced(top)
        self._build_actions(top)
        self._build_log()

    def _build_io(self, parent: ttk.Frame) -> None:
        lf = ttk.LabelFrame(parent, text="Input / Output", padding=self._PAD)
        lf.grid(sticky="ew", pady=(0, self._PAD))
        lf.columnconfigure(1, weight=1)

        ttk.Label(lf, text="Input folder(s):").grid(row=0, column=0, sticky="nw", padx=(0, 6))

        folder_frame = ttk.Frame(lf)
        folder_frame.grid(row=0, column=1, sticky="ew")
        folder_frame.columnconfigure(0, weight=1)

        self._folder_listbox = tk.Listbox(folder_frame, height=3, selectmode=tk.SINGLE)
        self._folder_listbox.grid(row=0, column=0, sticky="ew")
        sb = ttk.Scrollbar(folder_frame, orient=tk.VERTICAL, command=self._folder_listbox.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self._folder_listbox.configure(yscrollcommand=sb.set)

        btn_frame = ttk.Frame(folder_frame)
        btn_frame.grid(row=1, column=0, columnspan=2, sticky="w", pady=(2, 0))
        ttk.Button(btn_frame, text="Add folder…", command=self._add_folder).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_frame, text="Remove selected", command=self._remove_folder).pack(side=tk.LEFT)

        ttk.Label(lf, text="Output file:").grid(
            row=1, column=0, sticky="w", padx=(0, 6), pady=(self._PAD, 0)
        )
        out_frame = ttk.Frame(lf)
        out_frame.grid(row=1, column=1, sticky="ew", pady=(self._PAD, 0))
        out_frame.columnconfigure(0, weight=1)
        self._output_var = tk.StringVar()
        ttk.Entry(out_frame, textvariable=self._output_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(out_frame, text="Browse…", command=self._browse_output).grid(
            row=0, column=1, padx=(4, 0)
        )

        ttk.Label(lf, text="Case name:").grid(
            row=2, column=0, sticky="w", padx=(0, 6), pady=(self._PAD, 0)
        )
        self._case_name_var = tk.StringVar()
        ttk.Entry(lf, textvariable=self._case_name_var).grid(
            row=2, column=1, sticky="ew", pady=(self._PAD, 0)
        )

    def _build_flags(self, parent: ttk.Frame) -> None:
        lf = ttk.LabelFrame(parent, text="Options", padding=self._PAD)
        lf.grid(sticky="ew", pady=(0, self._PAD))

        flags = [
            ("Analysis_Summary sheet",    "summary",           False),
            ("Timeline sheet",            "timeline",          False),
            ("Highlight suspicious rows", "highlight",         False),
            ("ATT&CK technique column",   "attck",             False),
            ("Process tree sheet",        "process_tree",      False),
            ("Decode -EncodedCommand",    "decode_encoded",    False),
            ("IOC extract sheet",         "ioc_extract",       False),
            ("Escape formula injection",  "escape_formulas",   False),
            ("Use CSV filename as sheet", "use_filename",      False),
            ("Add source filename col",   "add_source_column", False),
            ("Recursive subfolder search","recursive",         False),
        ]

        self._flag_vars: dict[str, tk.BooleanVar] = {}
        for i, (label, attr, default) in enumerate(flags):
            var = tk.BooleanVar(value=default)
            self._flag_vars[attr] = var
            col = (i % 2) * 2
            row = i // 2
            ttk.Checkbutton(lf, text=label, variable=var).grid(
                row=row, column=col, sticky="w", padx=(0, 24), pady=2
            )

    def _build_advanced(self, parent: ttk.Frame) -> None:
        lf = ttk.LabelFrame(parent, text="Advanced", padding=self._PAD)
        lf.grid(sticky="ew", pady=(0, self._PAD))
        lf.columnconfigure(1, weight=1)

        ttk.Label(lf, text="Columns filter:").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self._columns_var = tk.StringVar()
        ttk.Entry(lf, textvariable=self._columns_var).grid(row=0, column=1, sticky="ew")
        ttk.Label(lf, text='e.g. "Timestamp,ImageFileName,CommandLine"', foreground="gray").grid(
            row=0, column=2, sticky="w", padx=(8, 0)
        )

        ttk.Label(lf, text="Max rows per sheet:").grid(
            row=1, column=0, sticky="w", padx=(0, 6), pady=(self._PAD, 0)
        )
        self._max_rows_var = tk.StringVar()
        ttk.Entry(lf, textvariable=self._max_rows_var, width=12).grid(
            row=1, column=1, sticky="w", pady=(self._PAD, 0)
        )

    def _build_actions(self, parent: ttk.Frame) -> None:
        frame = ttk.Frame(parent)
        frame.grid(sticky="ew", pady=(0, self._PAD))

        self._run_btn = ttk.Button(frame, text="Run", command=self._run, width=12)
        self._run_btn.pack(side=tk.LEFT, padx=(0, 6))

        self._open_btn = ttk.Button(
            frame, text="Open output", command=self._open_output,
            state=tk.DISABLED, width=14,
        )
        self._open_btn.pack(side=tk.LEFT, padx=(0, 6))

        ttk.Button(frame, text="Clear log", command=self._clear_log).pack(side=tk.LEFT)

        self._status_var = tk.StringVar(value="Ready")
        ttk.Label(frame, textvariable=self._status_var, foreground="gray").pack(side=tk.RIGHT)

    def _build_log(self) -> None:
        lf = ttk.LabelFrame(self, text="Output log", padding=self._PAD)
        lf.grid(row=1, column=0, sticky="nsew", padx=self._PAD, pady=(0, self._PAD))
        lf.rowconfigure(0, weight=1)
        lf.columnconfigure(0, weight=1)

        self._log_text = scrolledtext.ScrolledText(
            lf,
            state=tk.DISABLED,
            font=("Courier New", 10),
            background="#1E1E1E",
            foreground="#D4D4D4",
            insertbackground="#D4D4D4",
            wrap=tk.WORD,
            height=14,
        )
        self._log_text.grid(sticky="nsew")

        for level, color in self._LOG_TAG_COLORS.items():
            self._log_text.tag_configure(f"lvl_{level}", foreground=color)
        self._log_text.tag_configure("success", foreground="#70AD47")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _add_folder(self) -> None:
        path = filedialog.askdirectory(title="Select folder containing CSV files")
        if path and path not in self._input_folders:
            self._input_folders.append(path)
            self._folder_listbox.insert(tk.END, path)

    def _remove_folder(self) -> None:
        sel = self._folder_listbox.curselection()
        if sel:
            idx = sel[0]
            self._input_folders.pop(idx)
            self._folder_listbox.delete(idx)

    def _browse_output(self) -> None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Default the save dialog to the first input folder so the workbook
        # lands somewhere the user already has write access to.
        initial_dir = self._input_folders[0] if self._input_folders else str(Path.home())
        path = filedialog.asksaveasfilename(
            title="Save workbook as",
            defaultextension=".xlsx",
            filetypes=[("Excel workbook", "*.xlsx"), ("All files", "*.*")],
            initialfile=f"edr_analysis_{ts}.xlsx",
            initialdir=initial_dir,
        )
        if path:
            self._output_var.set(path)

    def _open_output(self) -> None:
        if not self._last_output or not self._last_output.exists():
            return
        p = str(self._last_output)
        if sys.platform == "win32":
            import os
            os.startfile(p)
        elif sys.platform == "darwin":
            subprocess.run(["open", p])
        else:
            subprocess.run(["xdg-open", p])

    def _clear_log(self) -> None:
        self._log_text.configure(state=tk.NORMAL)
        self._log_text.delete("1.0", tk.END)
        self._log_text.configure(state=tk.DISABLED)

    def _run(self) -> None:
        if self._running:
            return

        if not self._input_folders:
            messagebox.showerror("Missing input", "Please add at least one input folder.")
            return

        max_rows: Optional[int] = None
        raw_max = self._max_rows_var.get().strip()
        if raw_max:
            try:
                max_rows = int(raw_max)
                if max_rows <= 0:
                    raise ValueError
            except ValueError:
                messagebox.showerror("Invalid value", "Max rows must be a positive integer.")
                return

        columns_filter: Optional[list[str]] = None
        raw_cols = self._columns_var.get().strip()
        if raw_cols:
            columns_filter = [c.strip() for c in raw_cols.split(",") if c.strip()]

        output_path = (
            Path(self._output_var.get().strip())
            if self._output_var.get().strip() else None
        )
        case_name = self._case_name_var.get().strip() or None
        flags = {k: v.get() for k, v in self._flag_vars.items()}

        self._running = True
        self._run_btn.configure(state=tk.DISABLED)
        self._open_btn.configure(state=tk.DISABLED)
        self._status_var.set("Running…")
        self._last_output = None

        threading.Thread(
            target=self._run_worker,
            args=(self._input_folders[:], output_path, case_name, flags, columns_filter, max_rows),
            daemon=True,
        ).start()

    def _run_worker(
        self,
        folders: list[str],
        output_path: Optional[Path],
        case_name: Optional[str],
        flags: dict,
        columns_filter: Optional[list[str]],
        max_rows: Optional[int],
    ) -> None:
        handler = _QueueHandler(self._log_queue)
        handler.setFormatter(logging.Formatter("%(levelname)-8s %(message)s"))
        pkg_logger = logging.getLogger("edr_workbook_builder")
        pkg_logger.addHandler(handler)
        pkg_logger.setLevel(logging.DEBUG)
        pkg_logger.propagate = False

        result_path: Optional[Path] = None
        try:
            from edr_workbook_builder.config import get_extra_lolbins, load_config
            from edr_workbook_builder.csv_loader import find_csv_files, load_all_csvs
            from edr_workbook_builder.patterns import configure_lolbins
            from edr_workbook_builder.process_detection import detect_process_name
            from edr_workbook_builder.sheet_names import make_unique_sheet_names
            from edr_workbook_builder.workbook import build_workbook

            cfg = load_config()
            extra = get_extra_lolbins(cfg)
            if extra:
                configure_lolbins(extra)

            timestamp = datetime.now()

            csv_files: list[Path] = []
            for folder_str in folders:
                folder = Path(folder_str)
                found = find_csv_files(folder, recursive=flags.get("recursive", False))
                if not found:
                    pkg_logger.warning("No CSV files found in: %s", folder)
                csv_files.extend(found)

            if not csv_files:
                raise RuntimeError("No CSV files found across all input folders.")

            pkg_logger.info("Found %d CSV file(s)", len(csv_files))

            load_results = load_all_csvs(csv_files)

            process_names: list[Optional[str]] = []
            raw_names: list[str] = []
            for res in load_results:
                if flags.get("use_filename"):
                    proc_name = None
                elif res.dataframe is not None and not res.dataframe.empty:
                    proc_name = detect_process_name(res.dataframe)
                else:
                    proc_name = None
                process_names.append(proc_name)
                raw_names.append(proc_name if proc_name else res.path.stem)
            sheet_names = make_unique_sheet_names(raw_names)

            ts = timestamp.strftime("%Y%m%d_%H%M%S")
            if output_path is None:
                if case_name:
                    slug = "".join(
                        c if c.isalnum() or c in "-_" else "_" for c in case_name
                    )[:50]
                    filename = f"edr_analysis_{slug}_{ts}.xlsx"
                else:
                    filename = f"edr_analysis_{ts}.xlsx"
                # Default to the first input folder so we write somewhere writable.
                output_path = Path(folders[0]) / filename
            else:
                # Ensure .xlsx extension even if the user typed a bare name.
                if output_path.suffix.lower() != ".xlsx":
                    output_path = output_path.with_suffix(".xlsx")
                # A bare filename with no directory component is ambiguous —
                # resolve it into the first input folder rather than wherever
                # Python's cwd happens to be (often read-only on managed machines).
                if not output_path.parent.name:
                    output_path = Path(folders[0]) / output_path.name

            for res, sname, pname in zip(load_results, sheet_names, process_names):
                if res.error:
                    pkg_logger.warning("SKIP  %s — %s", res.path.name, res.error)
                else:
                    if flags.get("use_filename"):
                        tag = "(filename)"
                    elif pname:
                        tag = f"(process: {pname})"
                    else:
                        tag = "(fallback: filename)"
                    pkg_logger.info(
                        "SHEET %-35s %5d rows  %s", res.path.name, res.row_count, tag
                    )

            wb_result = build_workbook(
                load_results=load_results,
                sheet_names=sheet_names,
                process_names=process_names,
                output_path=output_path,
                case_name=case_name,
                add_summary=flags.get("summary", False),
                add_source_column=flags.get("add_source_column", False),
                timestamp=timestamp,
                highlight_suspicious=flags.get("highlight", False),
                escape_formulas=flags.get("escape_formulas", False),
                add_timeline=flags.get("timeline", False),
                add_attck=flags.get("attck", False),
                add_process_tree=flags.get("process_tree", False),
                decode_encoded=flags.get("decode_encoded", False),
                add_ioc_sheet=flags.get("ioc_extract", False),
                columns_filter=columns_filter,
                max_rows=max_rows,
            )

            result_path = output_path

            successful = sum(1 for r in load_results if r.error is None)
            failed     = sum(1 for r in load_results if r.error is not None)
            total_rows = sum(r.row_count for r in load_results if r.error is None)

            pkg_logger.info("---")
            pkg_logger.info("Workbook: %s", output_path)
            pkg_logger.info(
                "Sheets: %d  |  Total rows: %s",
                successful, f"{total_rows:,}",
            )
            if failed:
                pkg_logger.warning("Skipped: %d file(s) — check log above", failed)
            if wb_result.decoded_command_count:
                pkg_logger.info("Decoded: %d command(s)", wb_result.decoded_command_count)
            if flags.get("process_tree") and wb_result.process_tree_node_count:
                pkg_logger.info("ProcessTree: %d node(s)", wb_result.process_tree_node_count)
            if flags.get("ioc_extract") and wb_result.ioc_count:
                pkg_logger.info("IOC_Extract: %d indicator(s)", wb_result.ioc_count)

        except Exception as exc:
            pkg_logger.error("%s", exc)
        finally:
            pkg_logger.removeHandler(handler)
            pkg_logger.propagate = True
            self.after(0, self._on_complete, result_path)

    def _on_complete(self, result_path: Optional[Path]) -> None:
        self._running = False
        self._run_btn.configure(state=tk.NORMAL)

        if result_path:
            self._last_output = result_path
            self._open_btn.configure(state=tk.NORMAL)
            self._status_var.set(f"Done — {result_path.name}")
            self._append_log("✓ Workbook created successfully", "success")
        else:
            self._status_var.set("Failed — see log for details")

    # ------------------------------------------------------------------
    # Log helpers
    # ------------------------------------------------------------------

    def _poll_log_queue(self) -> None:
        fmt = logging.Formatter("%(levelname)-8s %(message)s")
        try:
            while True:
                record = self._log_queue.get_nowait()
                tag = f"lvl_{record.levelno}"
                self._append_log(fmt.format(record), tag)
        except queue.Empty:
            pass
        self.after(100, self._poll_log_queue)

    def _append_log(self, text: str, tag: str = f"lvl_{logging.INFO}") -> None:
        self._log_text.configure(state=tk.NORMAL)
        self._log_text.insert(tk.END, text + "\n", tag)
        self._log_text.see(tk.END)
        self._log_text.configure(state=tk.DISABLED)


def run() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    run()