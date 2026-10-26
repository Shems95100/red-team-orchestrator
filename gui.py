#!/usr/bin/env python3
"""Advanced GUI launcher for the Red Team Orchestrator."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

ROOT_DIR = Path(__file__).resolve().parent
MAIN_SCRIPT = ROOT_DIR / "main.py"


class RedTeamLauncherGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Red Team Orchestrator // Tactical Operations Console")
        self.root.geometry("1080x780")
        self.root.minsize(960, 680)
        self.root.configure(bg="#050b16")

        self.proc = None

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#050b16")
        style.configure("TLabel", background="#050b16", foreground="#e5edf9", font=("Segoe UI", 10))
        style.configure("Header.TLabel", background="#050b16", foreground="#f8fbff", font=("Segoe UI", 18, "bold"))
        style.configure("TEntry", fieldbackground="#111827", foreground="#e5edf9", insertcolor="#e5edf9")
        style.configure("TCombobox", fieldbackground="#111827", foreground="#e5edf9")
        style.configure("TCheckbutton", background="#050b16", foreground="#e5edf9")
        style.configure("TButton", background="#111827", foreground="#f8fbff", font=("Segoe UI", 10, "bold"))
        style.map("TButton", background=[("active", "#1e293b")])
        style.configure("Accent.TButton", background="#ef4444", foreground="#fff", font=("Segoe UI", 10, "bold"))
        style.map("Accent.TButton", background=[("active", "#b91c1c")])
        style.configure("Warn.TButton", background="#1d4ed8", foreground="#fff", font=("Segoe UI", 10, "bold"))
        style.map("Warn.TButton", background=[("active", "#1e40af")])

        header = ttk.Frame(root, padding=(18, 18, 18, 8))
        header.pack(fill="x")
        ttk.Label(header, text="TACTICAL ORCHESTRATOR // RED TEAM SUITE", style="Header.TLabel").pack(anchor="w")
        ttk.Label(header, text="Usage autorisé uniquement — périmètre défini dans scope.yaml", foreground="#a5b4cf").pack(anchor="w", pady=(4, 0))

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True, padx=18, pady=(0, 12))

        dashboard_tab = ttk.Frame(notebook, padding=12)
        mission_tab = ttk.Frame(notebook, padding=12)
        controls_tab = ttk.Frame(notebook, padding=12)
        logs_tab = ttk.Frame(notebook, padding=12)
        notebook.add(dashboard_tab, text="Dashboard")
        notebook.add(mission_tab, text="Mission")
        notebook.add(controls_tab, text="Contrôles")
        notebook.add(logs_tab, text="Logs")

        self.scope_var = tk.StringVar(value="scope.yaml")
        self.targets_var = tk.StringVar(value="192.168.56.101")
        self.report_var = tk.StringVar(value="rapport.md")
        self.nvd_key_var = tk.StringVar(value="")
        self.stealth_var = tk.StringVar(value="quiet")
        self.mode_var = tk.StringVar(value="audit")
        self.demo_mode = tk.BooleanVar(value=False)
        self.auto_mode = tk.BooleanVar(value=False)
        self.allow_exploit = tk.BooleanVar(value=False)
        self.allow_data_access = tk.BooleanVar(value=False)
        self.allow_service_shutdown = tk.BooleanVar(value=False)
        self.allow_web_shutdown = tk.BooleanVar(value=False)
        self.require_evidence = tk.BooleanVar(value=False)
        self.dry_run = tk.BooleanVar(value=False)
        self.verbose = tk.BooleanVar(value=False)

        self.log_box = scrolledtext.ScrolledText(logs_tab, wrap=tk.WORD, width=120, height=26, bg="#0b1020", fg="#dfe9ff", insertbackground="#dfe9ff", font=("Consolas", 9))
        self.log_box.pack(fill="both", expand=True)

        self.kpi_labels = {}
        self.dashboard_summary = ttk.Frame(dashboard_tab)
        self.dashboard_summary.pack(fill="x", pady=(0, 12))
        self._add_kpi_card(self.dashboard_summary, "Scope", "Authorized", "#60a5fa")
        self._add_kpi_card(self.dashboard_summary, "Targets", "0", "#f59e0b")
        self._add_kpi_card(self.dashboard_summary, "Exploit", "Guarded", "#22c55e")
        self._add_kpi_card(self.dashboard_summary, "Severity", "low", "#ef4444")
        self._add_kpi_card(self.dashboard_summary, "Stealth", "quiet", "#a78bfa")

        mission_status = ttk.Frame(dashboard_tab)
        mission_status.pack(fill="both", expand=True)
        ttk.Label(mission_status, text="Mission state", font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 6))
        self.mission_status = tk.Text(mission_status, height=10, width=110, bg="#0b1020", fg="#dfe9ff", insertbackground="#dfe9ff", font=("Consolas", 9))
        self.mission_status.pack(fill="both", expand=True)
        self.mission_status.insert("1.0", "[READY] Tactical console online in audit-only mode.\n[INFO] Exploitation and post-exploitation are disabled by default.\n[INFO] Web audit uses low-impact public metadata paths only.\n[INFO] Availability/DoS tests are never run.\n")
        self.mission_status.configure(state="disabled")

        self._build_field(mission_tab, "Scope file", self.scope_var, browse=True)
        self._build_field(mission_tab, "Targets", self.targets_var)
        self._build_field(mission_tab, "Report file", self.report_var, browse=True, save=True)
        self._build_field(mission_tab, "NVD key (optionnel)", self.nvd_key_var)

        row1 = ttk.Frame(mission_tab)
        row1.pack(fill="x", pady=6)
        ttk.Label(row1, text="Stealth", width=18).pack(side="left")
        stealth_combo = ttk.Combobox(row1, textvariable=self.stealth_var, state="readonly", width=18)
        stealth_combo["values"] = ("ghost", "quiet", "normal")
        stealth_combo.pack(side="left")

        ttk.Label(row1, text="Mode", width=12).pack(side="left", padx=(18, 8))
        mode_combo = ttk.Combobox(row1, textvariable=self.mode_var, state="readonly", width=16)
        mode_combo["values"] = ("exploit", "validate", "audit")
        mode_combo.pack(side="left")

        self._add_checkbox_row(mission_tab, [
            ("Demo mode", self.demo_mode),
            ("Bot auto", self.auto_mode),
            ("--allow-exploit", self.allow_exploit),
            ("--require-evidence", self.require_evidence),
            ("--dry-run", self.dry_run),
            ("--verbose", self.verbose),
        ])

        self._add_checkbox_row(controls_tab, [
            ("allow data access", self.allow_data_access),
            ("allow service stop", self.allow_service_shutdown),
            ("allow web disable", self.allow_web_shutdown),
        ])

        severity_row = ttk.Frame(controls_tab)
        severity_row.pack(fill="x", pady=10)
        ttk.Label(severity_row, text="Exploit severity", width=18).pack(side="left")
        self.severity_var = tk.StringVar(value="low")
        severity_combo = ttk.Combobox(severity_row, textvariable=self.severity_var, state="readonly", width=18)
        severity_combo["values"] = ("low", "medium", "high", "critical")
        severity_combo.pack(side="left")

        controls = ttk.Frame(root)
        controls.pack(fill="x", padx=18, pady=(0, 18))

        ttk.Button(controls, text="Lancer la mission", style="Accent.TButton", command=self.run_mission).pack(side="left", padx=(0, 10))
        ttk.Button(controls, text="Démo active", style="Warn.TButton", command=self.run_demo).pack(side="left", padx=(0, 10))
        ttk.Button(controls, text="Mode web focus", command=lambda: self._set_preset("web")).pack(side="left", padx=(0, 10))
        ttk.Button(controls, text="Mode AD focus", command=lambda: self._set_preset("ad")).pack(side="left", padx=(0, 10))
        ttk.Button(controls, text="Ouvrir rapport", command=self.open_report).pack(side="left", padx=(0, 10))
        ttk.Button(controls, text="Vider logs", command=self.clear_logs).pack(side="left")

        self._refresh_dashboard()
        self.log_box.insert(tk.END, "[READY] Red Team Orchestrator prêt.\n")
        self.log_box.configure(state="disabled")

    def _add_kpi_card(self, parent, label: str, value: str, accent: str) -> None:
        card = ttk.Frame(parent, padding=(14, 10))
        card.pack(side="left", expand=True, fill="x", padx=(0, 8))
        frame = tk.Frame(card, bg="#0b1220", padx=10, pady=10, highlightbackground=accent, highlightthickness=2)
        frame.pack(fill="both", expand=True)
        tk.Label(frame, text=label, bg="#0b1220", fg="#8aa4d1", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        value_label = tk.Label(frame, text=value, bg="#0b1220", fg="#f8fbff", font=("Segoe UI", 15, "bold"))
        value_label.pack(anchor="w", pady=(4, 0))
        self.kpi_labels[label] = value_label

    def _refresh_dashboard(self) -> None:
        targets = len(self._targets_list())
        self._set_dashboard_value("Targets", str(targets))
        self._set_dashboard_value("Exploit", "Active" if self.allow_exploit.get() or self.demo_mode.get() else "Guarded")
        self._set_dashboard_value("Severity", self.severity_var.get())
        self._set_dashboard_value("Stealth", self.stealth_var.get())
        self._set_dashboard_value("Scope", "Authorized" if Path(self.scope_var.get()).exists() else "Pending")

    def _set_dashboard_value(self, label: str, value: str) -> None:
        if label in self.kpi_labels:
            self.kpi_labels[label].configure(text=value)

    def _build_field(self, parent, label_text: str, variable: tk.StringVar, browse: bool = False, save: bool = False):
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=6)
        ttk.Label(row, text=label_text, width=18).pack(side="left")
        entry = ttk.Entry(row, textvariable=variable, width=70)
        entry.pack(side="left", fill="x", expand=True, padx=(8, 10))
        if browse:
            btn = ttk.Button(row, text="Parcourir", command=lambda: self._choose_file(variable, save))
            btn.pack(side="left")

    def _set_preset(self, mode: str) -> None:
        if mode == "web":
            self.stealth_var.set("quiet")
            self.mode_var.set("exploit")
            self.demo_mode.set(True)
            self.allow_exploit.set(True)
            self.severity_var.set("low")
            self.require_evidence.set(False)
            self.targets_var.set("192.168.56.101,192.168.56.120")
            self._refresh_dashboard()
            self._append_log("[PRESET] Web focus mission armed.\n")
        elif mode == "ad":
            self.stealth_var.set("ghost")
            self.mode_var.set("exploit")
            self.demo_mode.set(True)
            self.allow_exploit.set(True)
            self.severity_var.set("medium")
            self.require_evidence.set(False)
            self.targets_var.set("192.168.56.10,192.168.56.11")
            self._refresh_dashboard()
            self._append_log("[PRESET] Active Directory focus mission armed.\n")

    def _add_checkbox_row(self, parent, items):
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=6)
        for label, var in items:
            ttk.Checkbutton(row, text=label, variable=var).pack(side="left", padx=(0, 18))

    def _choose_file(self, variable: tk.StringVar, save: bool) -> None:
        if save:
            path = filedialog.asksaveasfilename(defaultextension=".md", initialfile=variable.get())
        else:
            path = filedialog.askopenfilename(initialdir=str(ROOT_DIR), title="Choisir un fichier")
        if path:
            variable.set(path)

    def _targets_list(self) -> list[str]:
        text = self.targets_var.get().strip().replace("\n", ",")
        return [item.strip() for item in text.split(",") if item.strip()]

    def _build_command(self, demo: bool = False) -> list[str]:
        command = [sys.executable, str(MAIN_SCRIPT), "--scope", self.scope_var.get().strip()]
        targets = self._targets_list()
        if targets:
            command.extend(["--targets", *targets])

        report = self.report_var.get().strip() or "rapport.md"
        command.extend(["--report", report])
        command.extend(["--stealth", self.stealth_var.get().strip()])

        if self.nvd_key_var.get().strip():
            command.extend(["--nvd-key", self.nvd_key_var.get().strip()])

        if demo or self.demo_mode.get():
            command.append("--demo")
            return command
        if self.auto_mode.get():
            command.append("--auto")
            return command

        command.extend(["--mode", self.mode_var.get().strip()])
        if self.allow_exploit.get():
            command.append("--allow-exploit")
        if self.allow_data_access.get():
            command.append("--allow-data-access")
        if self.allow_service_shutdown.get():
            command.append("--allow-service-stop")
        if self.allow_web_shutdown.get():
            command.append("--allow-web-disable")
        if self.dry_run.get():
            command.append("--dry-run")
        if self.verbose.get():
            command.append("--verbose")
        if not self.require_evidence.get():
            command.append("--no-require-evidence")
        command.extend(["--exploit-min-severity", self.severity_var.get().strip()])
        return command

    def _append_log(self, text: str) -> None:
        self.log_box.configure(state="normal")
        self.log_box.insert(tk.END, text)
        self.log_box.see(tk.END)
        self.log_box.configure(state="disabled")

    def clear_logs(self) -> None:
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", tk.END)
        self.log_box.insert(tk.END, "[CLEAR] Logs réinitialisés.\n")
        self.log_box.configure(state="disabled")

    def open_report(self) -> None:
        report_path = Path(self.report_var.get().strip() or "rapport.html")
        candidate = report_path if report_path.exists() else ROOT_DIR / report_path
        if candidate.exists():
            try:
                if os.name == "nt":
                    os.startfile(str(candidate))
                else:
                    os.system(f"xdg-open '{candidate}'")
            except Exception as exc:
                messagebox.showerror("Erreur", f"Impossible d'ouvrir le rapport : {exc}")
        else:
            messagebox.showwarning("Rapport", "Le rapport n'existe pas encore. Lance d'abord la mission.")

    def run_mission(self) -> None:
        self._execute(demo=False)

    def run_demo(self) -> None:
        self._execute(demo=True)

    def _execute(self, demo: bool = False) -> None:
        scope = Path(self.scope_var.get().strip())
        targets = self._targets_list()
        if not scope.exists():
            messagebox.showerror("Erreur", "Le fichier scope est introuvable.")
            return
        if not targets:
            messagebox.showerror("Erreur", "Renseigne au moins une cible.")
            return

        command = self._build_command(demo=demo)
        self._append_log(f"\n[CMD] {' '.join(command)}\n")

        try:
            self.proc = subprocess.Popen(command, cwd=str(ROOT_DIR), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            self._stream_output(self.proc)
        except Exception as exc:
            self._append_log(f"[ERROR] {exc}\n")
            messagebox.showerror("Erreur", f"Impossible de lancer la mission : {exc}")

    def _stream_output(self, proc: subprocess.Popen) -> None:
        def worker() -> None:
            assert proc.stdout is not None
            for line in proc.stdout:
                self._append_log(line)
            return_code = proc.wait()
            self.root.after(0, lambda: self._end_run(return_code))

        threading.Thread(target=worker, daemon=True).start()

    def _end_run(self, return_code: int) -> None:
        if return_code == 0:
            self._append_log("\n[OK] Mission terminée avec succès.\n")
            messagebox.showinfo("Succès", "La mission a été exécutée avec succès.")
        else:
            self._append_log(f"\n[FAIL] Mission terminée avec code {return_code}.\n")
            messagebox.showerror("Erreur", f"La mission a échoué avec le code {return_code}.")


def main() -> None:
    root = tk.Tk()
    RedTeamLauncherGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
