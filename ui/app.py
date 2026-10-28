"""Main CustomTkinter application shell and task orchestration."""

from __future__ import annotations

import os
import threading
from typing import Callable

import customtkinter as ctk

from core.constants import APP_NAME, APP_VERSION, COLORS
from core.logger import get_logger, setup_logging
from core.models import AuditReport, HardenResult
from core.services import Services
from core.settings import load_theme, save_theme
from core.winapi import (
    apply_dark_titlebar,
    asset_path,
    center_window,
    is_admin as process_is_admin,
)
from ui.components import LogConsole, Sidebar
from ui.dashboard import DashboardPage
from ui.firewall_page import FirewallPage
from ui.network_page import NetworkPage
from ui.privacy_page import PrivacyPage
from ui.theme import apply_theme, display_font, ui_font
from ui.tools_page import ToolsPage

LOG = get_logger("ui.app")


class WinSentinelApp(ctk.CTk):
    """The application shell. All service work runs on background threads."""

    def __init__(self, services: Services | None = None):
        setup_logging()
        theme_mode = load_theme("dark")
        apply_theme(theme_mode)
        super().__init__(fg_color=COLORS["bg"])

        self.services = services or Services()
        self.theme_mode = theme_mode
        self.is_admin = process_is_admin()
        self.audit_report: AuditReport | None = None
        self.scanning = False
        self.hardening = False
        self._running_tasks: set[str] = set()
        self._current_page = "dashboard"
        self._toast_job: str | None = None
        self._toast: ctk.CTkFrame | None = None
        self._closed = False

        self.title(f"{APP_NAME} — Windows Security")
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        width = min(1000, max(860, screen_w - 32))
        height = min(700, max(560, screen_h - 96))
        center_window(self, width, height)
        self.minsize(min(960, width), min(620, height))
        self._set_icon()
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._build_shell()
        self.sidebar.set_status("Starting", "Preparing first audit…", COLORS["accent"])

        self.after(250, lambda: apply_dark_titlebar(self, dark=self.theme_mode == "dark"))
        self.after(650, lambda: self.start_audit(source="startup", silent=True))
        self.after(1000, lambda: self._reset_page_scroll(self._current_page))

        LOG.info(
            "%s v%s started · admin=%s · theme=%s · session user=%s",
            APP_NAME,
            APP_VERSION,
            self.is_admin,
            self.theme_mode,
            os.environ.get("USERNAME", "unknown"),
        )
        if not self.is_admin:
            LOG.warning("Standard user context: remediation and network changes are disabled.")

    # ------------------------------------------------------------------
    def _build_shell(self) -> None:
        self.configure(fg_color=COLORS["bg"])

        self.sidebar = Sidebar(
            self,
            self._show_page,
            on_toggle_theme=self._toggle_theme,
            theme_mode=self.theme_mode,
        )
        self.sidebar.grid(row=0, column=0, rowspan=2, sticky="nsw")
        self.sidebar.set_admin(self.is_admin)

        self.page_container = ctk.CTkFrame(self, fg_color=COLORS["bg"], corner_radius=0)
        self.page_container.grid(row=0, column=1, sticky="nsew")
        self.page_container.grid_columnconfigure(0, weight=1)
        self.page_container.grid_rowconfigure(0, weight=1)

        self.pages = {
            "dashboard": DashboardPage(self.page_container, self),
            "network": NetworkPage(self.page_container, self),
            "firewall": FirewallPage(self.page_container, self),
            "privacy": PrivacyPage(self.page_container, self),
            "tools": ToolsPage(self.page_container, self),
        }
        for page in self.pages.values():
            page.grid(row=0, column=0, sticky="nsew")
        self.pages["dashboard"].tkraise()

        self.log_console = LogConsole(self)
        self.log_console.grid(
            row=1,
            column=1,
            sticky="ew",
            padx=(12, 12),
            pady=(0, 10),
        )
        self.log_console.lift()

        if self.audit_report is not None:
            self.pages["dashboard"].update_report(self.audit_report)
            self._update_sidebar_for_report(self.audit_report)
        else:
            self.sidebar.set_status(
                "Ready",
                "First audit runs automatically…",
                COLORS["accent"],
            )

    def _rebuild_shell(self, current_page: str) -> None:
        self._hide_toast()
        for attribute in ("log_console", "page_container", "sidebar"):
            widget = getattr(self, attribute, None)
            if widget is not None:
                try:
                    widget.destroy()
                except Exception:
                    pass
                setattr(self, attribute, None)
        self.pages = {}
        self._build_shell()
        self._show_page(current_page)

    def _toggle_theme(self) -> None:
        if self._running_tasks or self.scanning or self.hardening:
            self.sidebar.set_theme_mode(self.theme_mode)
            self.show_toast(
                "Wait for the current operation to finish before switching themes.",
                "warning",
            )
            return

        current_page = self._current_page
        new_mode = "light" if self.theme_mode == "dark" else "dark"
        self.theme_mode = new_mode
        save_theme(new_mode)
        apply_theme(new_mode)
        self._rebuild_shell(current_page)
        self.after(80, lambda: apply_dark_titlebar(self, dark=new_mode == "dark"))
        LOG.info("Theme switched to %s", new_mode)
        self.show_toast(f"{new_mode.title()} theme applied", "success", duration=2200)

    # ------------------------------------------------------------------
    def _set_icon(self) -> None:
        icon = asset_path("winsentinel.ico")
        try:
            if icon.exists():
                self.iconbitmap(str(icon))
        except Exception:
            pass

    def _show_page(self, key: str) -> None:
        page = self.pages.get(key)
        if page is None:
            return
        self._current_page = key
        page.tkraise()
        self._reset_page_scroll(key)
        if hasattr(page, "on_show"):
            page.on_show()
        self.after(60, lambda: self._reset_page_scroll(key))

    def _reset_page_scroll(self, key: str) -> None:
        page = self.pages.get(key)
        scroll = getattr(page, "scroll", None) if page else None
        if scroll is not None:
            try:
                scroll._parent_canvas.yview_moveto(0)
            except Exception:
                pass

    # ------------------------------------------------------------------
    def run_task(
        self,
        key: str,
        work: Callable,
        on_success: Callable | None = None,
        on_error: Callable | None = None,
        on_done: Callable | None = None,
    ) -> bool:
        """Run ``work`` in a daemon thread and marshal callbacks to Tk's thread."""

        if key in self._running_tasks:
            return False
        self._running_tasks.add(key)

        def worker() -> None:
            try:
                result = work()
            except Exception as exc:  # noqa: BLE001 - surfaced through the UI
                LOG.exception("Background task '%s' failed: %s", key, exc)
                self._post(self._finish_task, key, on_error, exc, on_done)
            else:
                self._post(self._finish_task, key, on_success, result, on_done)

        thread = threading.Thread(target=worker, name=f"winsentinel-{key}", daemon=True)
        thread.start()
        return True

    def _finish_task(
        self,
        key: str,
        callback: Callable | None,
        result_or_error,
        on_done: Callable | None,
    ) -> None:
        self._running_tasks.discard(key)
        try:
            if callback:
                callback(result_or_error)
        except Exception:
            LOG.exception("UI callback for '%s' failed", key)
        finally:
            if on_done:
                try:
                    on_done()
                except Exception:
                    LOG.exception("UI completion callback for '%s' failed", key)

    def _post(self, callback: Callable, *args) -> None:
        if self._closed:
            return
        try:
            self.after(0, lambda: callback(*args))
        except Exception:
            pass

    # ------------------------------------------------------------------
    def start_audit(self, source: str = "manual", silent: bool = False) -> bool:
        if self.scanning or self.hardening:
            if source == "manual":
                self.show_toast("A scan or hardening run is already in progress.", "warning")
            return False
        if "audit" in self._running_tasks:
            return False

        self.scanning = True
        self.pages["dashboard"].set_scanning(True)
        self.sidebar.set_status("Scanning", "Checking Windows protections…", COLORS["accent"])
        LOG.info("Starting security audit (source=%s)", source)

        def progress(done: int, total: int, label: str) -> None:
            if total <= 0:
                return
            self._post(self._on_audit_progress, done, total, label)

        def work() -> AuditReport:
            return self.services.auditor.scan(progress)

        def success(report: AuditReport) -> None:
            self.audit_report = report
            self.pages["dashboard"].update_report(report)
            self._update_sidebar_for_report(report)
            if not silent:
                kind = "success" if not report.issues else "warning"
                self.show_toast(
                    f"Scan complete · {report.score}/100 · {len(report.issues)} issue(s)",
                    kind,
                )

        def error(exc: Exception) -> None:
            LOG.error("Security audit failed: %s", exc)
            self.sidebar.set_status("Scan failed", str(exc), COLORS["danger"])
            self.show_toast(f"Security audit failed: {exc}", "error")

        def done() -> None:
            self.scanning = False
            self.pages["dashboard"].set_scanning(False)

        return self.run_task("audit", work, success, error, done)

    def _on_audit_progress(self, done: int, total: int, label: str) -> None:
        self.pages["dashboard"].set_progress(done / max(1, total), f"{label}  ({done}/{total})")

    def _update_sidebar_for_report(self, report: AuditReport) -> None:
        if report.counts["fail"]:
            state = "Attention"
            color = COLORS["danger"]
        elif report.counts["warn"] or report.counts["unknown"]:
            state = "Review"
            color = COLORS["warning"]
        else:
            state = "Protected"
            color = COLORS["success"]
        self.sidebar.set_status(
            state,
            f"Score {report.score}/100 · {len(report.issues)} issue(s)",
            color,
        )

    # ------------------------------------------------------------------
    def start_hardening(self) -> bool:
        if not self.is_admin:
            self.show_toast(
                "Harden My PC needs administrator rights. Restart WinSentinel elevated.",
                "warning",
            )
            return False
        if self.scanning or self.hardening:
            self.show_toast("Wait for the current operation to finish.", "warning")
            return False
        if "hardening" in self._running_tasks:
            return False

        self.hardening = True
        self.pages["dashboard"].set_hardening(True)
        self.sidebar.set_status("Hardening", "Applying safe security fixes…", COLORS["accent"])
        LOG.info("One-click hardening requested")

        def progress(done: int, total: int, label: str) -> None:
            if total:
                self._post(self._on_audit_progress, done, total, label)

        def work() -> tuple[HardenResult, AuditReport | None]:
            report = self.audit_report
            if report is None:
                report = self.services.auditor.scan(progress)
            self._post(self.pages["dashboard"].set_progress, 0.08, "Applying remediation pipeline…")
            result = self.services.hardener.harden(report)
            try:
                final = self.services.auditor.scan(progress)
            except Exception as exc:
                LOG.exception("Post-hardening verification scan failed: %s", exc)
                final = None
            return result, final

        def success(payload: tuple[HardenResult, AuditReport | None]) -> None:
            result, final = payload
            for step in result.steps:
                LOG.info("Hardening step: %s", step.message)
                for detail in step.details:
                    LOG.info("  %s", detail)
            if final is not None:
                self.audit_report = final
                self.pages["dashboard"].update_report(final)
                self._update_sidebar_for_report(final)

            applied = sum(1 for step in result.steps if step.success and not step.skipped)
            failed = sum(1 for step in result.steps if not step.success and not step.skipped)
            if result.success:
                message = f"Hardening complete · {applied} fix(es) applied"
                kind = "success"
            else:
                message = f"Hardening finished with {failed} failed step(s)"
                kind = "warning"
            if result.reboot_required:
                message += " · restart required for UAC"
            self.show_toast(message, kind, duration=7000)
            if final is None:
                self.show_toast(
                    "Hardening applied, but the verification scan failed. Run Full Scan.",
                    "warning",
                    duration=7000,
                )

        def error(exc: Exception) -> None:
            LOG.error("Hardening failed: %s", exc)
            self.sidebar.set_status("Hardening failed", str(exc), COLORS["danger"])
            self.show_toast(f"Hardening failed: {exc}", "error")

        def done() -> None:
            self.hardening = False
            self.pages["dashboard"].set_hardening(False)

        return self.run_task("hardening", work, success, error, done)

    # ------------------------------------------------------------------
    def refresh_security_pages(self) -> None:
        """Re-scan posture in the background after a settings change."""

        if self.scanning or self.hardening:
            return
        self.after(350, lambda: self.start_audit(source="sync", silent=True))

    # ------------------------------------------------------------------
    def show_toast(self, message: str, kind: str = "info", duration: int = 4600) -> None:
        colors = {
            "success": COLORS["success"],
            "error": COLORS["danger"],
            "warning": COLORS["warning"],
            "info": COLORS["accent"],
        }
        color = colors.get(kind, COLORS["accent"])
        if self._toast_job:
            try:
                self.after_cancel(self._toast_job)
            except Exception:
                pass
            self._toast_job = None
        if self._toast is not None:
            try:
                self._toast.destroy()
            except Exception:
                pass
            self._toast = None

        toast = ctk.CTkFrame(
            self,
            fg_color=COLORS["card"],
            corner_radius=9,
            border_width=1,
            border_color=COLORS["border_bright"],
        )
        toast.place(relx=1.0, x=-16, y=58, anchor="ne")
        ctk.CTkLabel(
            toast,
            text="●",
            font=ui_font(8),
            text_color=color,
            width=13,
        ).pack(side="left", padx=(10, 3), pady=9)
        ctk.CTkLabel(
            toast,
            text=message,
            font=ui_font(9),
            text_color=COLORS["text"],
            justify="left",
            wraplength=320,
        ).pack(side="left", padx=(0, 12), pady=8)
        toast.lift()
        self._toast = toast
        self._toast_job = self.after(duration, self._hide_toast)

    def _hide_toast(self) -> None:
        if self._toast is not None:
            try:
                self._toast.destroy()
            except Exception:
                pass
            self._toast = None
        self._toast_job = None

    # ------------------------------------------------------------------
    def _on_close(self) -> None:
        self._closed = True
        LOG.info("%s shutting down", APP_NAME)
        try:
            self.destroy()
        except Exception:
            pass
