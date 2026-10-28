"""Security utilities: passphrase generator and Wi-Fi hardening helper."""

from __future__ import annotations

from tkinter import BooleanVar, StringVar
from typing import TYPE_CHECKING

import customtkinter as ctk

from core.constants import COLORS
from core.logger import get_logger
from core.models import Finding, Status
from core.security_tools import ROUTER_CHECKLIST, build_wifi_hardening_script
from core.winapi import get_default_gateway, open_url
from ui.components import (
    Card,
    InfoBanner,
    PageHeader,
    SectionLabel,
    StatusPill,
    make_primary_button,
    make_secondary_button,
    status_color,
)
from ui.theme import mono_font, ui_font

if TYPE_CHECKING:
    from ui.app import WinSentinelApp

LOG = get_logger("ui.tools")


class ToolsPage(ctk.CTkFrame):
    def __init__(self, master, app: "WinSentinelApp", **kwargs):
        super().__init__(master, fg_color=COLORS["bg"], **kwargs)
        self.app = app
        self._current_phrase = None
        self._gateway = ""
        self._wifi_finding: Finding | None = None
        self._loading_wifi = False
        self.words_var = StringVar(value="7")
        self.number_var = BooleanVar(value=True)
        self.symbol_var = BooleanVar(value=True)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self.header = PageHeader(
            self,
            "Security Tools",
            "Offline utilities for stronger secrets and safer wireless.",
        )
        self.header.grid(row=0, column=0, sticky="ew", padx=18, pady=(14, 6))

        self.scroll = ctk.CTkScrollableFrame(
            self,
            fg_color="transparent",
            corner_radius=0,
            scrollbar_button_color=COLORS["border_bright"],
            scrollbar_button_hover_color=COLORS["text_dim"],
        )
        self.scroll.grid(row=1, column=0, sticky="nsew", padx=(8, 4), pady=(0, 4))
        self.scroll.grid_columnconfigure(0, weight=1, uniform="tools")
        self.scroll.grid_columnconfigure(1, weight=1, uniform="tools")

        self._build_passphrase_card()
        self._build_wifi_card()
        self._build_notes()

        self._generate_passphrase()

    # ------------------------------------------------------------------
    def _build_passphrase_card(self) -> None:
        card = Card(self.scroll)
        card.grid(row=0, column=0, sticky="nsew", padx=(6, 3), pady=(0, 10))
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            card,
            text="Passphrase generator",
            font=ui_font(13, "bold"),
            text_color=COLORS["text"],
            anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=13, pady=(12, 1))
        ctk.CTkLabel(
            card,
            text="Long, memorable phrases are harder to crack than short passwords.",
            font=ui_font(8),
            text_color=COLORS["text_dim"],
            anchor="w",
            justify="left",
            wraplength=320,
        ).grid(row=1, column=0, sticky="w", padx=13, pady=(0, 9))

        self.phrase_box = ctk.CTkTextbox(
            card,
            height=92,
            corner_radius=8,
            border_width=1,
            border_color=COLORS["border_bright"],
            fg_color=COLORS["input"],
            text_color=COLORS["text"],
            font=mono_font(13),
            wrap="word",
            activate_scrollbars=False,
        )
        self.phrase_box.grid(row=2, column=0, sticky="ew", padx=13)
        self.phrase_box.configure(state="disabled")

        stats = ctk.CTkFrame(card, fg_color="transparent")
        stats.grid(row=3, column=0, sticky="ew", padx=13, pady=(7, 0))
        stats.grid_columnconfigure(1, weight=1)
        self.strength_label = ctk.CTkLabel(
            stats,
            text="— bits",
            font=mono_font(9, "bold"),
            text_color=COLORS["success"],
            anchor="w",
        )
        self.strength_label.grid(row=0, column=0, sticky="w")
        self.strength_bar = ctk.CTkProgressBar(
            stats,
            height=3,
            corner_radius=1,
            fg_color=COLORS["border"],
            progress_color=COLORS["success"],
        )
        self.strength_bar.grid(row=0, column=1, sticky="ew", padx=(10, 0))
        self.strength_bar.set(0)
        self.length_label = ctk.CTkLabel(
            stats,
            text="",
            font=ui_font(8),
            text_color=COLORS["text_dim"],
            anchor="e",
        )
        self.length_label.grid(row=1, column=0, columnspan=2, sticky="e", pady=(2, 0))

        options = ctk.CTkFrame(card, fg_color="transparent")
        options.grid(row=4, column=0, sticky="ew", padx=13, pady=(9, 0))
        self.word_selector = ctk.CTkSegmentedButton(
            options,
            values=["6", "7", "8"],
            variable=self.words_var,
            width=132,
            height=26,
            corner_radius=6,
            fg_color=COLORS["card_muted"],
            selected_color=COLORS["accent"],
            selected_hover_color=COLORS["accent_hover"],
            unselected_color=COLORS["card_muted"],
            unselected_hover_color=COLORS["card_hover"],
            text_color=COLORS["text"],
            font=ui_font(9, "bold"),
        )
        self.word_selector.pack(side="left")
        ctk.CTkLabel(
            options,
            text="words",
            font=ui_font(8),
            text_color=COLORS["text_dim"],
        ).pack(side="left", padx=(5, 8))

        ctk.CTkCheckBox(
            options,
            text="Number",
            variable=self.number_var,
            font=ui_font(8),
            text_color=COLORS["text_muted"],
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            border_color=COLORS["border_bright"],
            checkmark_color=COLORS["accent_text"],
            checkbox_width=15,
            checkbox_height=15,
            corner_radius=3,
        ).pack(side="left", padx=(0, 7))
        ctk.CTkCheckBox(
            options,
            text="Symbol",
            variable=self.symbol_var,
            font=ui_font(8),
            text_color=COLORS["text_muted"],
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            border_color=COLORS["border_bright"],
            checkmark_color=COLORS["accent_text"],
            checkbox_width=15,
            checkbox_height=15,
            corner_radius=3,
        ).pack(side="left")

        buttons = ctk.CTkFrame(card, fg_color="transparent")
        buttons.grid(row=5, column=0, sticky="ew", padx=13, pady=(10, 0))
        make_primary_button(
            buttons,
            "Generate new",
            self._generate_passphrase,
            width=118,
            compact=True,
        ).pack(side="left")
        make_secondary_button(
            buttons,
            "Copy phrase",
            self._copy_phrase,
            width=98,
            compact=True,
        ).pack(side="left", padx=(6, 0))

        ctk.CTkLabel(
            card,
            text="Generated locally with a cryptographic RNG. Never logged or uploaded.",
            font=ui_font(8),
            text_color=COLORS["text_dim"],
            anchor="w",
            wraplength=320,
            justify="left",
        ).grid(row=6, column=0, sticky="w", padx=13, pady=(10, 12))

    # ------------------------------------------------------------------
    def _build_wifi_card(self) -> None:
        card = Card(self.scroll)
        card.grid(row=0, column=1, sticky="nsew", padx=(3, 6), pady=(0, 10))
        card.grid_columnconfigure(0, weight=1)

        top = ctk.CTkFrame(card, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=13, pady=(12, 0))
        top.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            top,
            text="Wi-Fi security helper",
            font=ui_font(13, "bold"),
            text_color=COLORS["text"],
            anchor="w",
        ).grid(row=0, column=0, sticky="w")
        self.wifi_pill = StatusPill(top, Status.INFO)
        self.wifi_pill.grid(row=0, column=1, sticky="e")
        ctk.CTkLabel(
            card,
            text="Audit the active association and prepare a router checklist.",
            font=ui_font(8),
            text_color=COLORS["text_dim"],
            anchor="w",
            justify="left",
            wraplength=320,
        ).grid(row=1, column=0, sticky="w", padx=13, pady=(1, 6))

        self.wifi_status = ctk.CTkLabel(
            card,
            text="Checking wireless state…",
            font=ui_font(9),
            text_color=COLORS["text_muted"],
            anchor="w",
            justify="left",
            wraplength=320,
        )
        self.wifi_status.grid(row=2, column=0, sticky="w", padx=13)

        self.checklist_label = ctk.CTkLabel(
            card,
            text="\n".join(f"•  {item}" for item in ROUTER_CHECKLIST),
            font=ui_font(8),
            text_color=COLORS["text_dim"],
            anchor="w",
            justify="left",
            wraplength=320,
        )
        self.checklist_label.grid(row=3, column=0, sticky="w", padx=13, pady=(7, 6))

        self.script_box = ctk.CTkTextbox(
            card,
            height=96,
            corner_radius=8,
            border_width=1,
            border_color=COLORS["border"],
            fg_color=COLORS["input"],
            text_color=COLORS["text_muted"],
            font=mono_font(7),
            wrap="word",
        )
        self.script_box.grid(row=4, column=0, sticky="ew", padx=13)
        self.script_box.configure(state="disabled")

        buttons = ctk.CTkFrame(card, fg_color="transparent")
        buttons.grid(row=5, column=0, sticky="ew", padx=13, pady=(9, 0))
        make_primary_button(
            buttons,
            "Copy PowerShell",
            self._copy_script,
            width=118,
            compact=True,
        ).pack(side="left")
        make_secondary_button(
            buttons,
            "Open router",
            self._open_router,
            width=88,
            compact=True,
        ).pack(side="left", padx=(6, 0))
        self.wifi_refresh_button = make_secondary_button(
            buttons,
            "Recheck",
            self._refresh_wifi,
            width=72,
            compact=True,
        )
        self.wifi_refresh_button.pack(side="right")

        ctk.CTkLabel(
            card,
            text="WPS and WPA mode are router-side settings. Windows cannot change them.",
            font=ui_font(8),
            text_color=COLORS["text_dim"],
            anchor="w",
            justify="left",
            wraplength=320,
        ).grid(row=6, column=0, sticky="w", padx=13, pady=(9, 11))

    def _build_notes(self) -> None:
        note = InfoBanner(
            self.scroll,
            "Utilities run entirely offline. Use a password manager and keep Windows updates on.",
            accent=COLORS["info"],
            glyph="i",
        )
        note.grid(row=1, column=0, columnspan=2, sticky="ew", padx=6, pady=(0, 10))

    # ------------------------------------------------------------------
    def _generate_passphrase(self) -> None:
        try:
            word_count = int(self.words_var.get() or "7")
            phrase = self.app.services.passphrases.generate(
                word_count,
                include_number=bool(self.number_var.get()),
                include_symbol=bool(self.symbol_var.get()),
            )
        except Exception as exc:
            self.app.show_toast(f"Could not generate a passphrase: {exc}", "error")
            return
        self._current_phrase = phrase
        self.phrase_box.configure(state="normal")
        self.phrase_box.delete("1.0", "end")
        self.phrase_box.insert("1.0", phrase.text)
        self.phrase_box.configure(state="disabled")

        color = status_color(
            Status.PASS if phrase.entropy >= 68 else Status.WARN if phrase.entropy >= 55 else Status.FAIL
        )
        self.strength_label.configure(
            text=f"{phrase.entropy:.0f} bits · {phrase.strength}",
            text_color=color,
        )
        self.strength_bar.configure(progress_color=color)
        self.strength_bar.set(min(1.0, phrase.entropy / 100))
        self.length_label.configure(
            text=f"{phrase.word_count} base words · {phrase.length} characters · {phrase.wordlist_size:,} word list"
        )
        # Deliberately never log the generated secret.

    def _copy_phrase(self) -> None:
        if not self._current_phrase:
            self._generate_passphrase()
        if self._current_phrase:
            self.clipboard_clear()
            self.clipboard_append(self._current_phrase.text)
            self.update_idletasks()
            self.app.show_toast("Passphrase copied to clipboard.", "success")

    # ------------------------------------------------------------------
    def _refresh_wifi(self) -> None:
        if self._loading_wifi:
            return
        self._loading_wifi = True
        self.wifi_refresh_button.configure(text="Checking…", state="disabled")

        def work():
            finding = self.app.services.auditor.audit_wifi()
            gateway = get_default_gateway()
            return finding, gateway

        self.app.run_task(
            "wifi_helper",
            work,
            self._on_wifi_loaded,
            self._on_wifi_error,
            on_done=self._finish_wifi,
        )

    def _finish_wifi(self) -> None:
        self._loading_wifi = False
        self.wifi_refresh_button.configure(text="Recheck", state="normal")

    def _on_wifi_loaded(self, data) -> None:
        finding, gateway = data
        self._wifi_finding = finding
        self._gateway = gateway
        evidence = finding.evidence
        self.wifi_pill.set_status(finding.status)
        connected = bool(evidence.get("connected"))
        if connected:
            ssid = evidence.get("ssid") or "unknown"
            auth = evidence.get("authentication") or "unknown"
            cipher = evidence.get("cipher") or "unknown"
            self.wifi_status.configure(
                text=(
                    f"{ssid}  ·  {auth}  ·  {cipher}\n"
                    f"{finding.summary}"
                ),
                text_color=COLORS["text"],
            )
        else:
            self.wifi_status.configure(
                text="No active Wi-Fi association found. The helper still includes router steps.",
                text_color=COLORS["text_muted"],
            )
        script = build_wifi_hardening_script(
            ssid=str(evidence.get("ssid") or ""),
            authentication=str(evidence.get("authentication") or ""),
            cipher=str(evidence.get("cipher") or ""),
            gateway=gateway,
        )
        self.script_box.configure(state="normal")
        self.script_box.delete("1.0", "end")
        self.script_box.insert("1.0", script)
        self.script_box.configure(state="disabled")
        LOG.info("Wi-Fi helper refreshed")

    def _on_wifi_error(self, error: Exception) -> None:
        LOG.error("Wi-Fi audit failed: %s", error)
        self.wifi_pill.set_status(Status.UNKNOWN)
        self.wifi_status.configure(text=f"Could not read Wi-Fi state: {error}")
        self.app.show_toast(f"Wi-Fi check failed: {error}", "error")
        script = build_wifi_hardening_script()
        self.script_box.configure(state="normal")
        self.script_box.delete("1.0", "end")
        self.script_box.insert("1.0", script)
        self.script_box.configure(state="disabled")

    def _copy_script(self) -> None:
        script = self.script_box.get("1.0", "end").strip()
        if not script:
            return
        self.clipboard_clear()
        self.clipboard_append(script)
        self.update_idletasks()
        self.app.show_toast("Wi-Fi hardening helper copied.", "success")

    def _open_router(self) -> None:
        gateway = self._gateway or get_default_gateway()
        if not gateway:
            self.app.show_toast("No default gateway was detected.", "warning")
            return
        self._gateway = gateway
        if open_url(f"http://{gateway}"):
            self.app.show_toast(f"Opening router admin at {gateway}…", "info")
        else:
            self.app.show_toast("Could not open the router page.", "error")

    def on_show(self) -> None:
        if self._wifi_finding is None and not self._loading_wifi:
            self._refresh_wifi()
