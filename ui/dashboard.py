"""Dashboard page: security score, live controls, and audit results."""

from __future__ import annotations

from typing import TYPE_CHECKING

import customtkinter as ctk

from core.constants import COLORS
from core.models import AuditReport, Status
from ui.components import (
    Card,
    FindingCard,
    InfoBanner,
    MiniMetric,
    PageHeader,
    ScoreGauge,
    make_primary_button,
    make_secondary_button,
    status_color,
)
from ui.theme import ui_font

if TYPE_CHECKING:
    from ui.app import WinSentinelApp


class DashboardPage(ctk.CTkFrame):
    def __init__(self, master, app: "WinSentinelApp", **kwargs):
        super().__init__(master, fg_color=COLORS["bg"], **kwargs)
        self.app = app
        self._report: AuditReport | None = None
        self._scanning = False
        self._hardening = False

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self.header = PageHeader(
            self,
            "Security overview",
            "A quick health check for this Windows PC.",
        )
        self.header.grid(row=0, column=0, sticky="ew", padx=18, pady=(14, 4))
        self.scan_button = make_secondary_button(
            self.header.actions,
            "Scan System",
            self._scan,
            width=100,
            compact=True,
        )
        self.scan_button.pack(side="left", padx=(0, 6))
        self.harden_button = make_primary_button(
            self.header.actions,
            "Harden My PC",
            self._harden,
            width=118,
            compact=True,
        )
        self.harden_button.pack(side="left")

        self.progress_row = ctk.CTkFrame(self, fg_color="transparent", height=16)
        self.progress_row.grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 2))
        self.progress_row.grid_columnconfigure(0, weight=1)
        self.progress = ctk.CTkProgressBar(
            self.progress_row,
            height=2,
            corner_radius=1,
            fg_color=COLORS["border"],
            progress_color=COLORS["accent"],
        )
        self.progress.grid(row=0, column=0, sticky="ew")
        self.progress.set(0)
        self.progress_label = ctk.CTkLabel(
            self.progress_row,
            text="Ready",
            font=ui_font(8),
            text_color=COLORS["text_dim"],
        )
        self.progress_label.grid(row=0, column=1, padx=(8, 0))
        self.progress_row.grid_remove()

        self.scroll = ctk.CTkScrollableFrame(
            self,
            fg_color="transparent",
            corner_radius=0,
            scrollbar_button_color=COLORS["border_bright"],
            scrollbar_button_hover_color=COLORS["text_dim"],
        )
        self.scroll.grid(row=2, column=0, sticky="nsew", padx=(8, 4), pady=0)
        self.scroll.grid_columnconfigure(0, weight=1)

        self.admin_banner = InfoBanner(
            self.scroll,
            "Standard user mode · audits work, but fixes are disabled. "
            "Restart WinSentinel as administrator to apply changes.",
            accent=COLORS["warning"],
        )
        self.admin_banner.grid(row=0, column=0, sticky="ew", padx=6, pady=(0, 8))
        self.admin_banner.grid_remove()
        if not self.app.is_admin:
            self.admin_banner.grid()

        self._build_hero()

        section = ctk.CTkFrame(self.scroll, fg_color="transparent")
        section.grid(row=2, column=0, sticky="ew", padx=6, pady=(12, 6))
        section.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            section,
            text="Security controls",
            font=ui_font(12, "bold"),
            text_color=COLORS["text"],
            anchor="w",
        ).grid(row=0, column=0, sticky="w")
        self.check_count = ctk.CTkLabel(
            section,
            text="AWAITING SCAN",
            font=ui_font(8, "bold"),
            text_color=COLORS["text_dim"],
            anchor="e",
        )
        self.check_count.grid(row=0, column=1, sticky="e")

        self.findings_grid = ctk.CTkFrame(self.scroll, fg_color="transparent")
        self.findings_grid.grid(row=3, column=0, sticky="nsew", padx=6, pady=(0, 10))
        self.findings_grid.grid_columnconfigure(0, weight=1, uniform="finding")
        self.findings_grid.grid_columnconfigure(1, weight=1, uniform="finding")

        self._render_placeholder()

        if not self.app.is_admin:
            self.harden_button.configure(state="disabled")

    # ------------------------------------------------------------------
    def _build_hero(self) -> None:
        self.hero = Card(self.scroll, height=212)
        self.hero.grid(row=1, column=0, sticky="ew", padx=6, pady=0)
        self.hero.grid_columnconfigure(1, weight=1)
        self.hero.grid_rowconfigure(0, weight=1)
        self.hero.grid_propagate(False)

        gauge_wrap = ctk.CTkFrame(self.hero, fg_color="transparent")
        gauge_wrap.grid(row=0, column=0, padx=(12, 4), pady=13)
        self.gauge = ScoreGauge(gauge_wrap, size=142)
        self.gauge.pack()

        narrative = ctk.CTkFrame(self.hero, fg_color="transparent")
        narrative.grid(row=0, column=1, sticky="nw", padx=(10, 8), pady=(20, 0))
        self.risk_kicker = ctk.CTkLabel(
            narrative,
            text="AUTOMATIC SECURITY AUDIT",
            font=ui_font(8, "bold"),
            text_color=COLORS["accent"],
            anchor="w",
        )
        self.risk_kicker.pack(anchor="w")
        self.risk_title = ctk.CTkLabel(
            narrative,
            text="Preparing your security report",
            font=ui_font(18, "bold"),
            text_color=COLORS["text"],
            anchor="w",
            justify="left",
            wraplength=400,
        )
        self.risk_title.pack(anchor="w", pady=(3, 3))
        self.risk_headline = ctk.CTkLabel(
            narrative,
            text="Checking Defender, firewall, DNS, Wi-Fi, browsers, and UAC.",
            font=ui_font(9),
            text_color=COLORS["text_muted"],
            anchor="w",
            justify="left",
            wraplength=400,
        )
        self.risk_headline.pack(anchor="w")
        self.meta_label = ctk.CTkLabel(
            narrative,
            text="First scan runs automatically",
            font=ui_font(8),
            text_color=COLORS["text_dim"],
            anchor="w",
        )
        self.meta_label.pack(anchor="w", pady=(9, 0))

        metrics = ctk.CTkFrame(self.hero, fg_color="transparent")
        metrics.grid(row=0, column=2, sticky="e", padx=(0, 12), pady=10)
        self.metric_pass = MiniMetric(metrics, "Protected", "—", COLORS["success"], width=82)
        self.metric_pass.pack(fill="x", pady=(0, 3))
        self.metric_warn = MiniMetric(metrics, "Warnings", "—", COLORS["warning"], width=82)
        self.metric_warn.pack(fill="x", pady=(0, 3))
        self.metric_fail = MiniMetric(metrics, "Critical", "—", COLORS["danger"], width=82)
        self.metric_fail.pack(fill="x")

    # ------------------------------------------------------------------
    def _render_placeholder(self) -> None:
        for child in self.findings_grid.winfo_children():
            child.destroy()
        for index, (title, code) in enumerate(
            (
                ("Windows Defender", "DEF"),
                ("Windows Firewall", "FW"),
                ("Private DNS", "DNS"),
                ("Wi-Fi Security", "WIFI"),
                ("Browser Privacy", "WEB"),
                ("User Account Control", "UAC"),
            )
        ):
            card = Card(self.findings_grid)
            card.grid(
                row=index // 2,
                column=index % 2,
                sticky="nsew",
                padx=(0, 3) if index % 2 == 0 else (3, 0),
                pady=3,
            )
            ctk.CTkLabel(
                card,
                text=code,
                width=34,
                height=30,
                corner_radius=7,
                fg_color=COLORS["card_muted"],
                text_color=COLORS["text_dim"],
                font=ui_font(8, "bold"),
            ).pack(side="left", padx=10, pady=11)
            data = ctk.CTkFrame(card, fg_color="transparent")
            data.pack(side="left", fill="both", expand=True, pady=11)
            ctk.CTkLabel(
                data,
                text=title,
                font=ui_font(10, "bold"),
                text_color=COLORS["text_muted"],
                anchor="w",
            ).pack(anchor="w")
            ctk.CTkLabel(
                data,
                text="Waiting for audit…",
                font=ui_font(8),
                text_color=COLORS["text_dim"],
                anchor="w",
            ).pack(anchor="w", pady=(2, 0))

    # ------------------------------------------------------------------
    def _scan(self) -> None:
        self.app.start_audit(source="dashboard")

    def _harden(self) -> None:
        self.app.start_hardening()

    def set_scanning(self, active: bool) -> None:
        self._scanning = active
        if active:
            self.scan_button.configure(text="Scanning…", state="disabled")
            self.harden_button.configure(state="disabled")
            self.progress_row.grid()
            self.progress.set(0)
            self.progress_label.configure(text="Starting…", text_color=COLORS["accent"])
        else:
            self.scan_button.configure(text="Scan System", state="normal")
            if self.app.is_admin and (self._report is None or self._report.issues):
                self.harden_button.configure(state="normal")
            else:
                self.harden_button.configure(state="disabled")
            self.progress_row.grid_remove()

    def set_hardening(self, active: bool) -> None:
        self._hardening = active
        if active:
            self.harden_button.configure(text="Hardening…", state="disabled")
            self.scan_button.configure(state="disabled")
            self.progress_row.grid()
            self.progress.set(0)
            self.progress_label.configure(
                text="Applying safe fixes…",
                text_color=COLORS["accent"],
            )
        else:
            self.harden_button.configure(text="Harden My PC")
            self.scan_button.configure(state="normal")
            if self.app.is_admin and (self._report is None or self._report.issues):
                self.harden_button.configure(state="normal")
            else:
                self.harden_button.configure(state="disabled")
            self.progress_row.grid_remove()

    def set_progress(self, value: float, message: str) -> None:
        self.progress_row.grid()
        self.progress.set(max(0.0, min(1.0, value)))
        self.progress_label.configure(text=message)

    # ------------------------------------------------------------------
    def update_report(self, report: AuditReport) -> None:
        self._report = report
        counts = report.counts
        self.gauge.set_score(report.score)
        self.metric_pass.set(str(counts["pass"]))
        self.metric_warn.set(str(counts["warn"] + counts["unknown"]))
        self.metric_fail.set(str(counts["fail"]))

        color = status_color(self._overall_status(report))
        self.risk_kicker.configure(
            text=f"{report.grade.upper()} · {report.risk_label.upper()}",
            text_color=color,
        )
        self.risk_title.configure(text=report.headline)
        self.risk_headline.configure(
            text=(
                f"{counts['pass']} protected · "
                f"{counts['warn'] + counts['unknown']} advisory · "
                f"{counts['fail']} critical"
            )
        )
        timestamp = report.finished_at.strftime("%b %d, %H:%M:%S")
        self.meta_label.configure(
            text=f"Last scan {timestamp} · {report.duration_seconds:.1f}s · {report.hostname}"
        )
        self.check_count.configure(
            text=f"{len(report.findings)} CHECKS · {report.score}/100",
            text_color=color,
        )
        self._render_findings(report)

        if report.issues and self.app.is_admin:
            self.harden_button.configure(state="normal")
        elif not report.issues:
            self.harden_button.configure(text="All Hardened", state="disabled")
        else:
            self.harden_button.configure(state="disabled")

    def _render_findings(self, report: AuditReport) -> None:
        for child in self.findings_grid.winfo_children():
            child.destroy()
        for index, finding in enumerate(report.findings):
            card = FindingCard(self.findings_grid, finding)
            card.grid(
                row=index // 2,
                column=index % 2,
                sticky="nsew",
                padx=(0, 3) if index % 2 == 0 else (3, 0),
                pady=3,
            )

    @staticmethod
    def _overall_status(report: AuditReport) -> Status:
        if report.counts["fail"]:
            return Status.FAIL
        if report.counts["warn"] or report.counts["unknown"]:
            return Status.WARN
        return Status.PASS

    def on_show(self) -> None:
        if self._report is not None:
            self.update_report(self._report)
        else:
            self._scan()
