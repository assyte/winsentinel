"""Browser extension policy page."""

from __future__ import annotations

from typing import TYPE_CHECKING

import customtkinter as ctk

from core.constants import BROWSERS, COLORS, BROWSER_BY_KEY
from core.logger import get_logger
from core.models import OperationResult, Status
from core.policy_manager import BrowserPolicyState
from ui.components import (
    Card,
    ConfirmDialog,
    InfoBanner,
    PageHeader,
    SectionLabel,
    StatusPill,
    make_primary_button,
    make_secondary_button,
)
from ui.theme import danger_button_kwargs, mono_font, ui_font

if TYPE_CHECKING:
    from ui.app import WinSentinelApp

LOG = get_logger("ui.privacy")


class PrivacyPage(ctk.CTkFrame):
    def __init__(self, master, app: "WinSentinelApp", **kwargs):
        super().__init__(master, fg_color=COLORS["bg"], **kwargs)
        self.app = app
        self._states: list[BrowserPolicyState] = []
        self._loading = False
        self._working = False

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self.header = PageHeader(
            self,
            "Browser & Privacy",
            "Force-install ad and tracker blockers through Windows policy.",
        )
        self.header.grid(row=0, column=0, sticky="ew", padx=18, pady=(14, 6))
        self.refresh_button = make_secondary_button(
            self.header.actions,
            "Refresh",
            self.refresh,
            width=78,
            compact=True,
        )
        self.refresh_button.pack(side="left")
        self.enforce_button = make_primary_button(
            self.header.actions,
            "Enforce blockers",
            self._enforce,
            width=122,
            compact=True,
        )
        self.enforce_button.pack(side="left", padx=(6, 0))

        self.scroll = ctk.CTkScrollableFrame(
            self,
            fg_color="transparent",
            corner_radius=0,
            scrollbar_button_color=COLORS["border_bright"],
            scrollbar_button_hover_color=COLORS["text_dim"],
        )
        self.scroll.grid(row=1, column=0, sticky="nsew", padx=(8, 4), pady=(0, 4))
        self.scroll.grid_columnconfigure(0, weight=1)

        self.banner = InfoBanner(
            self.scroll,
            "Reading browser extension policies…",
            accent=COLORS["accent"],
            glyph="i",
        )
        self.banner.grid(row=0, column=0, sticky="ew", padx=6, pady=(0, 10))

        section = ctk.CTkFrame(self.scroll, fg_color="transparent")
        section.grid(row=1, column=0, sticky="ew", padx=6, pady=(0, 4))
        section.grid_columnconfigure(0, weight=1)
        SectionLabel(
            section,
            "Detected browsers",
            "Machine-wide policy · applies to every profile.",
        ).grid(row=0, column=0, sticky="w")
        self.summary_label = ctk.CTkLabel(
            section,
            text="CHECKING",
            font=ui_font(8, "bold"),
            text_color=COLORS["text_dim"],
        )
        self.summary_label.grid(row=0, column=1, sticky="e")

        self.browser_container = ctk.CTkFrame(self.scroll, fg_color="transparent")
        self.browser_container.grid(row=2, column=0, sticky="ew", padx=6, pady=(0, 8))
        self.browser_container.grid_columnconfigure(0, weight=1)

        self._build_danger_zone()

    # ------------------------------------------------------------------
    def _build_danger_zone(self) -> None:
        row = ctk.CTkFrame(
            self.scroll,
            fg_color=COLORS["card_muted"],
            corner_radius=8,
            border_width=1,
            border_color=COLORS["border"],
        )
        row.grid(row=3, column=0, sticky="ew", padx=6, pady=(4, 10))
        row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            row,
            text="Remove forced extensions",
            font=ui_font(10, "bold"),
            text_color=COLORS["text"],
            anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(9, 0))
        ctk.CTkLabel(
            row,
            text="Only WinSentinel-managed blocker entries are removed. Other browser policies are preserved.",
            font=ui_font(8),
            text_color=COLORS["text_dim"],
            anchor="w",
            justify="left",
            wraplength=570,
        ).grid(row=1, column=0, sticky="w", padx=12, pady=(1, 9))
        remove = ctk.CTkButton(
            row,
            text="Remove policies",
            width=112,
            command=self._confirm_remove,
            **danger_button_kwargs(compact=True),
        )
        remove.grid(row=0, column=1, rowspan=2, padx=12, pady=9)

    # ------------------------------------------------------------------
    def refresh(self) -> None:
        if self._loading:
            return
        self._loading = True
        self.refresh_button.configure(text="Loading…", state="disabled")
        self.enforce_button.configure(state="disabled")
        self.app.run_task(
            "browser_refresh",
            self.app.services.policy_manager.get_all_browser_states,
            self._on_loaded,
            self._on_error,
            on_done=self._finish_loading,
        )

    def _finish_loading(self) -> None:
        self._loading = False
        self.refresh_button.configure(text="Refresh", state="normal")
        if not self._working:
            self.enforce_button.configure(state="normal")

    def _on_loaded(self, states: list[BrowserPolicyState]) -> None:
        self._states = states
        self._render_states()
        installed = [state for state in states if state.installed]
        if not installed:
            self.banner.label.configure(
                text="No Chrome or Edge installation was detected. Extension policies can still be applied before a browser is installed."
            )
            self.summary_label.configure(text="NO BROWSERS")
            return
        compliant = [state for state in installed if state.compliant]
        if len(compliant) == len(installed):
            self.banner.configure(fg_color=COLORS["success_soft"])
            self.banner.label.configure(
                text="Ad and tracker blockers are enforced for every detected browser. Restart any open browser to finish installation."
            )
            self.summary_label.configure(
                text=f"{len(compliant)}/{len(installed)} COMPLIANT",
                text_color=COLORS["success"],
            )
        else:
            self.banner.configure(fg_color=COLORS["warning_soft"])
            self.banner.label.configure(
                text="One or more browsers are missing a forced ad blocker. Enforcing blockers is safe and does not disable browser security."
            )
            self.summary_label.configure(
                text=f"{len(compliant)}/{len(installed)} COMPLIANT",
                text_color=COLORS["warning"],
            )

    def _render_states(self) -> None:
        for child in self.browser_container.winfo_children():
            child.destroy()
        for index, state in enumerate(self._states):
            card = self._browser_card(state)
            card.grid(row=index, column=0, sticky="ew", pady=(0, 5))

    def _browser_card(self, state: BrowserPolicyState) -> Card:
        card = Card(self.browser_container)
        card.grid_columnconfigure(1, weight=1)
        tile = ctk.CTkLabel(
            card,
            text="CHR" if state.browser.key == "chrome" else "EDG",
            width=38,
            height=34,
            corner_radius=8,
            fg_color=COLORS["accent_soft"] if state.installed else COLORS["card_muted"],
            text_color=COLORS["accent"] if state.installed else COLORS["text_dim"],
            font=mono_font(9, "bold"),
        )
        tile.grid(row=0, column=0, rowspan=2, padx=(11, 8), pady=(10, 0), sticky="nw")

        header = ctk.CTkFrame(card, fg_color="transparent")
        header.grid(row=0, column=1, columnspan=2, sticky="ew", padx=(0, 11), pady=(9, 0))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            header,
            text=state.browser.name,
            font=ui_font(11, "bold"),
            text_color=COLORS["text"],
            anchor="w",
        ).grid(row=0, column=0, sticky="w")
        if not state.installed:
            pill = StatusPill(header, Status.INFO)
            pill.grid(row=0, column=1, sticky="e")
            pill.set_text("Not installed")
        elif state.compliant:
            StatusPill(header, Status.PASS).grid(row=0, column=1, sticky="e")
        elif state.entries:
            StatusPill(header, Status.WARN).grid(row=0, column=1, sticky="e")
        else:
            StatusPill(header, Status.FAIL).grid(row=0, column=1, sticky="e")

        if not state.installed:
            summary = "Not detected on this PC. Policy can be prepared anyway."
        elif state.compliant:
            summary = f"Forced: {', '.join(state.extension_names)}"
        elif state.entries:
            summary = f"Managed: {', '.join(state.extension_names)} — coverage is incomplete"
        else:
            summary = "No forced ad or tracker blocker policy"
        ctk.CTkLabel(
            card,
            text=summary,
            font=ui_font(9),
            text_color=COLORS["text_muted"],
            anchor="w",
            justify="left",
            wraplength=620,
        ).grid(row=1, column=1, columnspan=2, sticky="w", padx=(0, 11), pady=(2, 0))

        if state.entries:
            chips = ctk.CTkFrame(card, fg_color="transparent")
            chips.grid(row=2, column=1, columnspan=2, sticky="w", padx=(0, 11), pady=(6, 0))
            for entry in state.entries:
                ctk.CTkLabel(
                    chips,
                    text=entry.name,
                    font=ui_font(7, "bold"),
                    text_color=COLORS["accent"],
                    fg_color=COLORS["accent_soft"],
                    corner_radius=5,
                    padx=6,
                    height=18,
                ).pack(side="left", padx=(0, 4))
                ctk.CTkLabel(
                    chips,
                    text=entry.extension_id[:10] + "…",
                    font=mono_font(7),
                    text_color=COLORS["text_dim"],
                ).pack(side="left", padx=(0, 8))

        card.grid_rowconfigure(3, minsize=10)
        return card

    # ------------------------------------------------------------------
    def _enforce(self) -> None:
        if self._working:
            return
        installed = [state.browser for state in self._states if state.installed]
        if not installed:
            installed = list(BROWSERS)
        self._working = True
        self.enforce_button.configure(text="Enforcing…", state="disabled")
        self.refresh_button.configure(state="disabled")
        LOG.info("Forcing browser blockers for %s", ", ".join(browser.name for browser in installed))
        self.app.run_task(
            "browser_enforce",
            lambda: self.app.services.policy_manager.enforce_browser_extensions(installed),
            self._on_enforce_done,
            self._on_operation_error,
            on_done=self._finish_working,
        )

    def _finish_working(self) -> None:
        self._working = False
        self.enforce_button.configure(text="Enforce blockers", state="normal")
        self.refresh_button.configure(state="normal")
        self.refresh()
        self.app.refresh_security_pages()

    def _on_enforce_done(self, result: OperationResult) -> None:
        self.app.show_toast(result.message, "success" if result.success else "error")
        for detail in result.details:
            LOG.info("Browser policy: %s", detail)

    def _confirm_remove(self) -> None:
        ConfirmDialog(
            self,
            title="Remove forced blocker policies?",
            message=(
                "uBlock Origin and Privacy Badger will no longer be force-installed. "
                "Other managed extensions and policies will be preserved. Browsers may "
                "remove the extensions at the next policy refresh."
            ),
            confirm_text="Remove policies",
            danger=True,
            on_confirm=self._remove,
        )

    def _remove(self) -> None:
        if self._working:
            return
        self._working = True
        self.refresh_button.configure(state="disabled")
        LOG.info("Removing WinSentinel browser extension policies")
        self.app.run_task(
            "browser_remove",
            self.app.services.policy_manager.remove_browser_extensions,
            self._on_remove_done,
            self._on_operation_error,
            on_done=self._finish_working,
        )

    def _on_remove_done(self, result: OperationResult) -> None:
        self.app.show_toast(result.message, "success" if result.success else "error")
        for detail in result.details:
            LOG.info("Browser policy: %s", detail)

    def _on_error(self, error: Exception) -> None:
        LOG.error("Browser policy refresh failed: %s", error)
        self.app.show_toast(f"Could not read browser policies: {error}", "error")

    def _on_operation_error(self, error: Exception) -> None:
        LOG.error("Browser policy operation failed: %s", error)
        self.app.show_toast(f"Browser policy change failed: {error}", "error")
        self.refresh()

    def on_show(self) -> None:
        self.refresh()
