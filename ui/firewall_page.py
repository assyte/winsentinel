"""Firewall profiles and Microsoft Defender controls."""

from __future__ import annotations

from typing import TYPE_CHECKING

import customtkinter as ctk

from core.constants import COLORS, FIREWALL_PROFILES
from core.logger import get_logger
from core.models import DefenderStatus, FirewallProfile, OperationResult, Status
from core.winapi import open_url
from ui.components import (
    Card,
    ConfirmDialog,
    PageHeader,
    StatusPill,
    make_danger_button,
    make_primary_button,
    make_secondary_button,
)
from ui.theme import mono_font, ui_font

if TYPE_CHECKING:
    from ui.app import WinSentinelApp

LOG = get_logger("ui.firewall")


class FirewallPage(ctk.CTkFrame):
    def __init__(self, master, app: "WinSentinelApp", **kwargs):
        super().__init__(master, fg_color=COLORS["bg"], **kwargs)
        self.app = app
        self._profiles: list[FirewallProfile] = []
        self._defender: DefenderStatus | None = None
        self._loading = False
        self._profile_switches: dict[str, ctk.CTkSwitch] = {}
        self._profile_pills: dict[str, StatusPill] = {}
        self._profile_detail: dict[str, ctk.CTkLabel] = {}

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self.header = PageHeader(
            self,
            "Firewall & Defender",
            "Switch core protections on or off with a full audit trail.",
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
        self.enable_all_button = make_primary_button(
            self.header.actions,
            "Enable all",
            self._enable_all,
            width=92,
            compact=True,
        )
        self.enable_all_button.pack(side="left", padx=(6, 0))
        self.disable_all_button = make_danger_button(
            self.header.actions,
            "Disable all",
            self._disable_all,
            width=94,
            compact=True,
        )
        self.disable_all_button.pack(side="left", padx=(6, 0))

        self.scroll = ctk.CTkScrollableFrame(
            self,
            fg_color="transparent",
            corner_radius=0,
            scrollbar_button_color=COLORS["border_bright"],
            scrollbar_button_hover_color=COLORS["text_dim"],
        )
        self.scroll.grid(row=1, column=0, sticky="nsew", padx=(8, 4), pady=(0, 4))
        self.scroll.grid_columnconfigure(0, weight=1)

        self._build_firewall_section()
        self._build_defender_section()
        self._set_controls_enabled(False)

    # ------------------------------------------------------------------
    def _build_firewall_section(self) -> None:
        self.firewall_card = Card(self.scroll)
        self.firewall_card.grid(row=0, column=0, sticky="ew", padx=6, pady=(0, 10))
        self.firewall_card.grid_columnconfigure(0, weight=1)

        top = ctk.CTkFrame(self.firewall_card, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=13, pady=(11, 0))
        top.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            top,
            text="Windows Firewall",
            font=ui_font(13, "bold"),
            text_color=COLORS["text"],
            anchor="w",
        ).grid(row=0, column=0, sticky="w")
        self.firewall_pill = StatusPill(top, Status.INFO)
        self.firewall_pill.grid(row=0, column=1, sticky="e")
        self.firewall_note = ctk.CTkLabel(
            self.firewall_card,
            text="All three Windows network profiles should be active. Inbound traffic is blocked unless an app explicitly allows it.",
            font=ui_font(8),
            text_color=COLORS["text_dim"],
            anchor="w",
            justify="left",
            wraplength=700,
        )
        self.firewall_note.grid(row=1, column=0, sticky="w", padx=13, pady=(2, 9))

        self.profiles_grid = ctk.CTkFrame(self.firewall_card, fg_color="transparent")
        self.profiles_grid.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 4))
        for column in range(3):
            self.profiles_grid.grid_columnconfigure(column, weight=1, uniform="profile")
        for index, profile_name in enumerate(FIREWALL_PROFILES):
            profile_card = ctk.CTkFrame(
                self.profiles_grid,
                fg_color=COLORS["card_muted"],
                corner_radius=8,
                border_width=1,
                border_color=COLORS["border"],
            )
            profile_card.grid(
                row=0,
                column=index,
                sticky="nsew",
                padx=(0, 3) if index < 2 else (0, 0),
                pady=3,
            )
            profile_card.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(
                profile_card,
                text=profile_name,
                font=ui_font(10, "bold"),
                text_color=COLORS["text"],
                anchor="w",
            ).grid(row=0, column=0, sticky="w", padx=10, pady=(9, 0))
            pill = StatusPill(profile_card, Status.INFO)
            pill.grid(row=0, column=1, sticky="e", padx=(0, 8), pady=(7, 0))
            self._profile_pills[profile_name] = pill
            detail = ctk.CTkLabel(
                profile_card,
                text="Inbound: —",
                font=ui_font(8),
                text_color=COLORS["text_muted"],
                anchor="w",
            )
            detail.grid(row=1, column=0, columnspan=2, sticky="w", padx=10, pady=(2, 0))
            self._profile_detail[profile_name] = detail
            switch = ctk.CTkSwitch(
                profile_card,
                text="Off",
                font=ui_font(8),
                text_color=COLORS["text_muted"],
                progress_color=COLORS["accent"],
                button_color=COLORS["text"],
                button_hover_color=COLORS["text"],
                fg_color=COLORS["border_bright"],
                switch_width=30,
                switch_height=15,
                command=lambda name=profile_name: self._toggle_profile(name),
            )
            switch.grid(row=2, column=0, columnspan=2, sticky="w", padx=10, pady=(7, 9))
            self._profile_switches[profile_name] = switch

        inbound_row = ctk.CTkFrame(
            self.firewall_card,
            fg_color=COLORS["card_muted"],
            corner_radius=8,
            border_width=1,
            border_color=COLORS["border"],
        )
        inbound_row.grid(row=3, column=0, sticky="ew", padx=13, pady=(5, 11))
        inbound_row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            inbound_row,
            text="Block unsolicited inbound traffic",
            font=ui_font(10, "bold"),
            text_color=COLORS["text"],
            anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=11, pady=(9, 0))
        ctk.CTkLabel(
            inbound_row,
            text="Apps can still be allowed explicitly.",
            font=ui_font(8),
            text_color=COLORS["text_dim"],
            anchor="w",
        ).grid(row=1, column=0, sticky="w", padx=11, pady=(1, 9))
        self.inbound_switch = ctk.CTkSwitch(
            inbound_row,
            text="",
            width=34,
            progress_color=COLORS["accent"],
            button_color=COLORS["text"],
            button_hover_color=COLORS["text"],
            fg_color=COLORS["border_bright"],
            switch_width=34,
            switch_height=18,
            command=self._toggle_inbound,
        )
        self.inbound_switch.grid(row=0, column=1, rowspan=2, padx=12, pady=10)

    def _build_defender_section(self) -> None:
        self.defender_card = Card(self.scroll)
        self.defender_card.grid(row=1, column=0, sticky="ew", padx=6, pady=(0, 10))
        self.defender_card.grid_columnconfigure(1, weight=1)

        top = ctk.CTkFrame(self.defender_card, fg_color="transparent")
        top.grid(row=0, column=0, columnspan=2, sticky="ew", padx=13, pady=(11, 0))
        top.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            top,
            text="Microsoft Defender",
            font=ui_font(13, "bold"),
            text_color=COLORS["text"],
            anchor="w",
        ).grid(row=0, column=0, sticky="w")
        self.defender_pill = StatusPill(top, Status.INFO)
        self.defender_pill.grid(row=0, column=1, sticky="e")

        self.defender_status = ctk.CTkLabel(
            self.defender_card,
            text="Reading Defender status…",
            font=ui_font(9),
            text_color=COLORS["text_muted"],
            anchor="w",
            justify="left",
            wraplength=680,
        )
        self.defender_status.grid(row=1, column=0, columnspan=2, sticky="w", padx=13, pady=(2, 2))

        self.defender_meta = ctk.CTkLabel(
            self.defender_card,
            text="",
            font=mono_font(8),
            text_color=COLORS["text_dim"],
            anchor="w",
            justify="left",
            wraplength=680,
        )
        self.defender_meta.grid(row=2, column=0, columnspan=2, sticky="w", padx=13, pady=(0, 8))

        switch_row = ctk.CTkFrame(
            self.defender_card,
            fg_color=COLORS["card_muted"],
            corner_radius=8,
            border_width=1,
            border_color=COLORS["border"],
        )
        switch_row.grid(row=3, column=0, columnspan=2, sticky="ew", padx=13, pady=(0, 8))
        switch_row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            switch_row,
            text="Real-time protection",
            font=ui_font(10, "bold"),
            text_color=COLORS["text"],
            anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=11, pady=(8, 0))
        ctk.CTkLabel(
            switch_row,
            text="Scans files, downloads, and processes as they appear.",
            font=ui_font(8),
            text_color=COLORS["text_dim"],
            anchor="w",
        ).grid(row=1, column=0, sticky="w", padx=11, pady=(1, 8))
        self.rt_switch = ctk.CTkSwitch(
            switch_row,
            text="",
            width=34,
            progress_color=COLORS["accent"],
            button_color=COLORS["text"],
            button_hover_color=COLORS["text"],
            fg_color=COLORS["border_bright"],
            switch_width=34,
            switch_height=18,
            command=self._toggle_realtime,
        )
        self.rt_switch.grid(row=0, column=1, rowspan=2, padx=12, pady=10)

        security_button = make_secondary_button(
            self.defender_card,
            "Open Windows Security",
            self._open_security,
            width=154,
            compact=True,
        )
        security_button.grid(row=4, column=0, sticky="w", padx=13, pady=(0, 9))

    # ------------------------------------------------------------------
    def _set_controls_enabled(self, enabled: bool) -> None:
        can_change = enabled and self.app.is_admin
        state = "normal" if can_change else "disabled"
        for switch in self._profile_switches.values():
            switch.configure(state=state)
        self.inbound_switch.configure(state=state)
        defender_can_change = can_change and bool(
            self._defender is not None and self._defender.available
        )
        self.rt_switch.configure(state="normal" if defender_can_change else "disabled")
        self.enable_all_button.configure(state=state)
        self.disable_all_button.configure(state=state)

    def refresh(self) -> None:
        if self._loading:
            return
        self._loading = True
        self.refresh_button.configure(text="Loading…", state="disabled")
        self.firewall_note.configure(text="Reading firewall profiles…")
        self.firewall_pill.set_status(Status.INFO)
        self._set_controls_enabled(False)
        self.app.run_task(
            "fw_refresh",
            lambda: (
                self.app.services.firewall_manager.get_profiles(),
                self.app.services.firewall_manager.get_defender_status(),
            ),
            self._on_loaded,
            self._on_error,
            on_done=self._finish_loading,
        )

    def _finish_loading(self) -> None:
        self._loading = False
        self.refresh_button.configure(text="Refresh", state="normal")
        self._set_controls_enabled(bool(self._profiles) and self._defender is not None)

    def _on_loaded(self, data) -> None:
        profiles, defender = data
        self._profiles = profiles
        self._defender = defender
        self._render_profiles()
        self._render_defender()

    def _on_error(self, error: Exception) -> None:
        LOG.error("Firewall/Defender refresh failed: %s", error)
        self.app.show_toast(f"Could not read protection status: {error}", "error")
        self.firewall_note.configure(
            text="Could not read protection status: " + str(error)
        )

    def _render_profiles(self) -> None:
        if not self._profiles:
            self.firewall_pill.set_status(Status.UNKNOWN)
            self.firewall_note.configure(text="Firewall profile data is unavailable.")
            return
        enabled_count = sum(1 for profile in self._profiles if profile.enabled)
        all_enabled = enabled_count == len(self._profiles) == 3
        inbound_blocked = all(profile.inbound_is_blocked for profile in self._profiles)
        if all_enabled and inbound_blocked:
            self.firewall_pill.set_status(Status.PASS)
            self.firewall_note.configure(
                text="All profiles are active and block unsolicited inbound traffic."
            )
        elif all_enabled:
            self.firewall_pill.set_status(Status.WARN)
            self.firewall_note.configure(
                text="Profiles are active, but inbound traffic is not blocked by default."
            )
        else:
            self.firewall_pill.set_status(Status.FAIL)
            self.firewall_note.configure(
                text=f"{enabled_count}/3 firewall profiles are active. Turn on every profile to stop unsolicited inbound connections."
            )
        for profile in self._profiles:
            switch = self._profile_switches.get(profile.name)
            if switch:
                if profile.enabled:
                    switch.select()
                else:
                    switch.deselect()
                switch.configure(text="On" if profile.enabled else "Off")
            self._profile_pills[profile.name].set_status(
                Status.PASS if profile.enabled else Status.FAIL
            )
            self._profile_detail[profile.name].configure(
                text=f"Inbound: {profile.default_inbound} · Outbound: {profile.default_outbound}"
            )
        if inbound_blocked:
            self.inbound_switch.select()
        else:
            self.inbound_switch.deselect()

    def _render_defender(self) -> None:
        defender = self._defender
        if defender is None:
            self.defender_pill.set_status(Status.UNKNOWN)
            return
        if not defender.available:
            self.defender_pill.set_status(Status.UNKNOWN)
            self.defender_status.configure(
                text="Microsoft Defender is not reporting status. A third-party antivirus may be managing protection."
            )
            self.defender_meta.configure(text=defender.raw_error)
            self.rt_switch.configure(state="disabled")
            return
        if defender.antivirus_enabled and defender.realtime_enabled:
            self.defender_pill.set_status(Status.PASS)
            self.defender_status.configure(text="Real-time protection is active.")
        elif not defender.antivirus_enabled:
            self.defender_pill.set_status(Status.FAIL)
            self.defender_status.configure(text="Antivirus protection is disabled.")
        else:
            self.defender_pill.set_status(Status.FAIL)
            self.defender_status.configure(text="Real-time protection is disabled.")
        if defender.realtime_enabled:
            self.rt_switch.select()
        else:
            self.rt_switch.deselect()
        signature = (
            f"Definitions {defender.signature_age_days}d old"
            if defender.signature_age_days is not None
            else "Definitions age unknown"
        )
        self.defender_meta.configure(
            text=(
                f"Antivirus {'on' if defender.antivirus_enabled else 'off'}  ·  "
                f"AM service {'on' if defender.am_service_enabled else 'off'}  ·  "
                f"{signature}  ·  Tamper protection: {defender.tamper_protection or 'unknown'}"
            )
        )

    # ------------------------------------------------------------------
    def _toggle_profile(self, profile_name: str) -> None:
        switch = self._profile_switches[profile_name]
        desired = bool(switch.get())
        if not desired:
            switch.select()  # visually keep protection on until confirmed
            ConfirmDialog(
                self,
                title=f"Turn off {profile_name} firewall?",
                message=(
                    "Disabling a firewall profile exposes this PC to unsolicited inbound "
                    "connections on that network type. This is not recommended."
                ),
                confirm_text="Turn off",
                danger=True,
                on_confirm=lambda: self._apply_profile(profile_name, False),
            )
            return
        self._apply_profile(profile_name, True)

    def _apply_profile(self, profile_name: str, enabled: bool) -> None:
        switch = self._profile_switches[profile_name]
        switch.configure(state="disabled")
        LOG.info("%s firewall profile -> %s", profile_name, "on" if enabled else "off")
        self.app.run_task(
            f"fw_profile_{profile_name}",
            lambda: self.app.services.firewall_manager.set_profile_enabled(profile_name, enabled),
            self._on_operation_done,
            self._on_operation_error,
            on_done=self.refresh,
        )

    def _enable_all(self) -> None:
        self.enable_all_button.configure(state="disabled")
        LOG.info("Enabling all firewall profiles")
        self.app.run_task(
            "fw_enable_all",
            lambda: self.app.services.firewall_manager.set_all_enabled(True),
            self._on_operation_done,
            self._on_operation_error,
            on_done=self.refresh,
        )

    def _disable_all(self) -> None:
        self.disable_all_button.configure(state="disabled")
        ConfirmDialog(
            self,
            title="Turn off Windows Firewall for all profiles?",
            message=(
                "This disables the Domain, Private, and Public firewall profiles. "
                "Unsolicited inbound connections will no longer be filtered until you "
                "turn them back on. Use this only for a short, intentional test."
            ),
            confirm_text="Disable all",
            danger=True,
            on_confirm=self._apply_disable_all,
            on_cancel=lambda: self._set_controls_enabled(True),
        )

    def _apply_disable_all(self) -> None:
        LOG.warning("Disabling all firewall profiles")
        self.app.run_task(
            "fw_disable_all",
            lambda: self.app.services.firewall_manager.set_all_enabled(False),
            self._on_operation_done,
            self._on_operation_error,
            on_done=self.refresh,
        )

    def _toggle_inbound(self) -> None:
        desired = bool(self.inbound_switch.get())
        if not desired:
            self.inbound_switch.select()
            ConfirmDialog(
                self,
                title="Reset inbound firewall default?",
                message=(
                    "Windows will return to its default inbound behavior. This is less "
                    "strict than explicitly blocking unsolicited connections."
                ),
                confirm_text="Reset",
                danger=True,
                on_confirm=lambda: self._apply_inbound(False),
            )
            return
        self._apply_inbound(True)

    def _apply_inbound(self, enabled: bool) -> None:
        self.inbound_switch.configure(state="disabled")
        self.app.run_task(
            "fw_inbound",
            lambda: self.app.services.firewall_manager.block_inbound(enabled),
            self._on_operation_done,
            self._on_operation_error,
            on_done=self.refresh,
        )

    def _toggle_realtime(self) -> None:
        desired = bool(self.rt_switch.get())
        if not desired:
            self.rt_switch.select()
            ConfirmDialog(
                self,
                title="Turn off real-time protection?",
                message=(
                    "Defender will stop scanning new files and downloads in real time. "
                    "Malware may execute before the next scheduled scan. This is strongly "
                    "discouraged."
                ),
                confirm_text="Turn off",
                danger=True,
                on_confirm=lambda: self._apply_realtime(False),
            )
            return
        self._apply_realtime(True)

    def _apply_realtime(self, enabled: bool) -> None:
        self.rt_switch.configure(state="disabled")
        LOG.info("Defender real-time protection -> %s", "on" if enabled else "off")
        self.app.run_task(
            "defender_rt",
            lambda: self.app.services.firewall_manager.set_realtime_protection(enabled),
            self._on_operation_done,
            self._on_operation_error,
            on_done=self.refresh,
        )

    def _on_operation_done(self, result: OperationResult) -> None:
        kind = "success" if result.success else "error"
        self.app.show_toast(result.message, kind)
        for detail in result.details:
            LOG.info("Firewall: %s", detail)
        if result.success:
            self.app.refresh_security_pages()

    def _on_operation_error(self, error: Exception) -> None:
        LOG.error("Protection operation failed: %s", error)
        self.app.show_toast(f"Operation failed: {error}", "error")
        self.refresh()

    def _open_security(self) -> None:
        if not open_url("windowsdefender://threatsettings"):
            self.app.show_toast("Could not open Windows Security.", "error")

    def on_show(self) -> None:
        self.refresh()
