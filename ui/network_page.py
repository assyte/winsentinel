"""DNS and active network adapter page."""

from __future__ import annotations

from typing import TYPE_CHECKING

import customtkinter as ctk
from tkinter import BooleanVar, StringVar

from core.auditor import classify_dns_servers
from core.constants import COLORS, DNS_PROVIDERS, DNS_PROVIDER_BY_KEY
from core.logger import get_logger
from core.models import AdapterInfo, OperationResult, Status
from ui.components import (
    Card,
    InfoBanner,
    PageHeader,
    SectionLabel,
    StatusPill,
    make_primary_button,
    make_secondary_button,
)
from ui.theme import ghost_button_kwargs, mono_font, ui_font

if TYPE_CHECKING:
    from ui.app import WinSentinelApp

LOG = get_logger("ui.network")


class ProviderTile(Card):
    def __init__(self, master, provider, variable: StringVar, on_select, **kwargs):
        super().__init__(master, **kwargs)
        self.provider = provider
        self._variable = variable
        self._on_select = on_select
        self.grid_columnconfigure(1, weight=1)

        self.radio = ctk.CTkRadioButton(
            self,
            text="",
            width=16,
            variable=variable,
            value=provider.key,
            command=lambda: self._on_select(provider.key),
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            border_color=COLORS["border_bright"],
            radiobutton_width=14,
            radiobutton_height=14,
        )
        self.radio.grid(row=0, column=0, rowspan=2, padx=(11, 6), pady=(12, 0), sticky="n")

        title_row = ctk.CTkFrame(self, fg_color="transparent")
        title_row.grid(row=0, column=1, columnspan=2, sticky="ew", padx=(0, 11), pady=(11, 0))
        title_row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            title_row,
            text=provider.name,
            font=ui_font(11, "bold"),
            text_color=COLORS["text"],
            anchor="w",
        ).grid(row=0, column=0, sticky="w")
        tag = ctk.CTkLabel(
            title_row,
            text=provider.tag,
            font=ui_font(6, "bold"),
            text_color=provider.accent,
            fg_color=COLORS["card_muted"],
            corner_radius=5,
            padx=6,
            height=18,
        )
        tag.grid(row=0, column=1, sticky="e")

        ctk.CTkLabel(
            self,
            text=provider.description,
            font=ui_font(8),
            text_color=COLORS["text_dim"],
            anchor="w",
            justify="left",
            wraplength=300,
        ).grid(row=1, column=1, columnspan=2, sticky="w", padx=(0, 11), pady=(3, 0))

        ctk.CTkLabel(
            self,
            text=provider.address_label,
            font=mono_font(8),
            text_color=provider.accent,
            anchor="w",
        ).grid(row=2, column=1, columnspan=2, sticky="w", padx=(0, 11), pady=(5, 11))

        self._bind_clicks(self, provider.key)

    def _bind_clicks(self, widget, key: str) -> None:
        try:
            widget.bind("<Button-1>", lambda _event: self._on_select(key), add="+")
        except Exception:
            pass
        for child in widget.winfo_children():
            self._bind_clicks(child, key)

    def set_selected(self, selected: bool) -> None:
        self.configure(
            border_color=COLORS["accent"] if selected else COLORS["border"],
            border_width=2 if selected else 1,
            fg_color=COLORS["card_hover"] if selected else COLORS["card"],
        )


class NetworkPage(ctk.CTkFrame):
    def __init__(self, master, app: "WinSentinelApp", **kwargs):
        super().__init__(master, fg_color=COLORS["bg"], **kwargs)
        self.app = app
        self._adapters: list[AdapterInfo] = []
        self._labels: dict[str, AdapterInfo] = {}
        self._selected_name = ""
        self._loading = False
        self._applying = False
        self.selected_provider = StringVar(value="cloudflare")
        self.apply_all = BooleanVar(value=False)
        self.tiles: dict[str, ProviderTile] = {}

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.header = PageHeader(
            self,
            "DNS & Network",
            "Choose a privacy-respecting resolver for active adapters.",
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
        self.apply_button = make_primary_button(
            self.header.actions,
            "Apply DNS",
            self._apply_dns,
            width=102,
            compact=True,
        )
        self.apply_button.pack(side="left", padx=(6, 0))

        self.scroll = ctk.CTkScrollableFrame(
            self,
            fg_color="transparent",
            corner_radius=0,
            scrollbar_button_color=COLORS["border_bright"],
            scrollbar_button_hover_color=COLORS["text_dim"],
        )
        self.scroll.grid(row=1, column=0, sticky="nsew", padx=(8, 4), pady=(0, 4))
        self.scroll.grid_columnconfigure(0, weight=1)

        self._build_adapter_card()
        self._build_provider_grid()
        self._build_notes()

    # ------------------------------------------------------------------
    def _build_adapter_card(self) -> None:
        self.adapter_card = Card(self.scroll)
        self.adapter_card.grid(row=0, column=0, sticky="ew", padx=6, pady=(0, 10))
        self.adapter_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            self.adapter_card,
            text="ACTIVE ADAPTER",
            font=ui_font(7, "bold"),
            text_color=COLORS["text_dim"],
            anchor="w",
        ).grid(row=0, column=0, columnspan=3, sticky="w", padx=12, pady=(11, 5))

        self.adapter_menu = ctk.CTkOptionMenu(
            self.adapter_card,
            values=["No active adapter"],
            width=280,
            height=30,
            corner_radius=8,
            fg_color=COLORS["input"],
            button_color=COLORS["border_bright"],
            button_hover_color=COLORS["text_dim"],
            dropdown_fg_color=COLORS["card"],
            dropdown_hover_color=COLORS["card_hover"],
            dropdown_text_color=COLORS["text"],
            text_color=COLORS["text"],
            font=ui_font(10),
            command=self._choose_adapter,
        )
        self.adapter_menu.grid(row=1, column=0, sticky="w", padx=(12, 10), pady=(0, 7))
        self.adapter_menu.set("Loading adapters…")

        self.adapter_pill = StatusPill(self.adapter_card, Status.INFO)
        self.adapter_pill.grid(row=1, column=1, sticky="w", pady=(0, 7))

        self.all_checkbox = ctk.CTkCheckBox(
            self.adapter_card,
            text="All active adapters",
            variable=self.apply_all,
            font=ui_font(9),
            text_color=COLORS["text_muted"],
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            border_color=COLORS["border_bright"],
            checkmark_color="#062f37",
            width=138,
            checkbox_width=15,
            checkbox_height=15,
            corner_radius=3,
        )
        self.all_checkbox.grid(row=1, column=2, sticky="e", padx=(10, 12), pady=(0, 7))
        self.all_checkbox.configure(state="disabled")

        self.adapter_detail = ctk.CTkLabel(
            self.adapter_card,
            text="Discovering the active internet connection…",
            font=ui_font(8),
            text_color=COLORS["text_dim"],
            anchor="w",
            justify="left",
            wraplength=680,
        )
        self.adapter_detail.grid(row=2, column=0, columnspan=3, sticky="w", padx=12, pady=(0, 11))

        self.reset_button = make_secondary_button(
            self.adapter_card,
            "Use automatic (DHCP)",
            self._reset_dhcp,
            width=148,
            compact=True,
        )
        self.reset_button.grid(row=3, column=0, sticky="w", padx=12, pady=(0, 11))

    def _build_provider_grid(self) -> None:
        section = ctk.CTkFrame(self.scroll, fg_color="transparent")
        section.grid(row=1, column=0, sticky="ew", padx=6, pady=(2, 4))
        section.grid_columnconfigure(0, weight=1)
        SectionLabel(
            section,
            "Resolver presets",
            "IPv4 + IPv6 · no browser restart required.",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            section,
            text="SELECT ONE",
            font=ui_font(7, "bold"),
            text_color=COLORS["text_dim"],
        ).grid(row=0, column=1, sticky="e")

        grid = ctk.CTkFrame(self.scroll, fg_color="transparent")
        grid.grid(row=2, column=0, sticky="ew", padx=6, pady=(0, 6))
        grid.grid_columnconfigure(0, weight=1, uniform="provider")
        grid.grid_columnconfigure(1, weight=1, uniform="provider")
        for index, provider in enumerate(DNS_PROVIDERS):
            tile = ProviderTile(grid, provider, self.selected_provider, self._choose_provider)
            tile.grid(
                row=index // 2,
                column=index % 2,
                sticky="nsew",
                padx=(0, 3) if index % 2 == 0 else (3, 0),
                pady=3,
            )
            self.tiles[provider.key] = tile
        self._refresh_tile_styles()

    def _build_notes(self) -> None:
        note = InfoBanner(
            self.scroll,
            "WinSentinel sets plain system DNS resolvers. It does not claim to enable "
            "DNS-over-HTTPS; browsers and Windows may negotiate encryption separately.",
            accent=COLORS["info"],
            glyph="i",
        )
        note.grid(row=3, column=0, sticky="ew", padx=6, pady=(6, 10))

    # ------------------------------------------------------------------
    def _choose_provider(self, key: str) -> None:
        self.selected_provider.set(key)
        self._refresh_tile_styles()

    def _refresh_tile_styles(self) -> None:
        selected = self.selected_provider.get()
        for key, tile in self.tiles.items():
            tile.set_selected(key == selected)

    def _choose_adapter(self, label: str) -> None:
        adapter = self._labels.get(label)
        if adapter:
            self._selected_name = adapter.name
            self._render_adapter(adapter)
            self._refresh_tile_styles()

    def _selected_adapter(self) -> AdapterInfo | None:
        return next(
            (adapter for adapter in self._adapters if adapter.name == self._selected_name),
            None,
        )

    def refresh(self) -> None:
        if self._loading:
            return
        self._loading = True
        self.refresh_button.configure(text="Loading…", state="disabled")
        self.adapter_menu.configure(state="disabled")
        self.app.run_task(
            "dns_refresh",
            self.app.services.dns_manager.list_active_adapters,
            self._on_adapters_loaded,
            self._on_refresh_error,
            on_done=self._finish_loading,
        )

    def _finish_loading(self) -> None:
        self._loading = False
        self.refresh_button.configure(text="Refresh", state="normal")
        if self._adapters:
            self.adapter_menu.configure(state="normal")
        else:
            self.adapter_menu.configure(state="disabled")

    def _on_adapters_loaded(self, adapters: list[AdapterInfo]) -> None:
        self._adapters = adapters
        self._labels = {}
        labels = []
        for adapter in adapters:
            label = f"{adapter.name}   ·   {adapter.ipv4_address or 'no IPv4'}"
            self._labels[label] = adapter
            labels.append(label)
        if not labels:
            labels = ["No active adapter"]
            self.adapter_menu.configure(values=labels, state="disabled")
            self.adapter_menu.set(labels[0])
            self.all_checkbox.configure(state="disabled")
            self.adapter_pill.set_status(Status.INFO)
            self.adapter_detail.configure(
                text="No adapter with an active IPv4 default route was found. Connect to the internet and refresh."
            )
            self.apply_button.configure(state="disabled")
            self.reset_button.configure(state="disabled")
            return

        previous = next((a for a in adapters if a.name == self._selected_name), None)
        selected = previous or adapters[0]
        self._selected_name = selected.name
        label = next(label for label, adapter in self._labels.items() if adapter.name == selected.name)
        self.adapter_menu.configure(values=labels, state="normal")
        self.adapter_menu.set(label)
        self.all_checkbox.configure(state="normal" if len(adapters) > 1 else "disabled")
        if len(adapters) <= 1:
            self.apply_all.set(False)
        self.apply_button.configure(state="normal")
        self.reset_button.configure(state="normal")
        self._render_adapter(selected)

    def _render_adapter(self, adapter: AdapterInfo) -> None:
        secure, providers = classify_dns_servers(adapter.dns_servers)
        if secure:
            self.adapter_pill.set_status(Status.PASS)
            summary = f"Privacy resolver · {', '.join(providers)}"
            color = COLORS["success"]
        elif adapter.dns_servers:
            self.adapter_pill.set_status(Status.WARN)
            summary = "Unverified or ISP resolver"
            color = COLORS["warning"]
        else:
            self.adapter_pill.set_status(Status.WARN)
            summary = "Automatic DNS (router/ISP)"
            color = COLORS["warning"]
        addresses = ", ".join(adapter.dns_servers) if adapter.dns_servers else "automatic"
        mode = "DHCP" if adapter.dhcp_enabled else "static"
        self.adapter_detail.configure(
            text=(
                f"{summary}   ·   DNS: {addresses}   ·   {mode}   ·   "
                f"Gateway: {adapter.gateway or 'n/a'}   ·   {adapter.description}"
            ),
            text_color=color,
        )

    def _on_refresh_error(self, error: Exception) -> None:
        self.app.show_toast(f"Could not load adapters: {error}", "error")
        self.adapter_menu.configure(values=["No active adapter"], state="disabled")
        self.adapter_menu.set("Adapter lookup failed")
        self.apply_button.configure(state="disabled")
        self.reset_button.configure(state="disabled")
        LOG.error("Adapter refresh failed: %s", error)

    # ------------------------------------------------------------------
    def _apply_dns(self) -> None:
        if self._applying:
            return
        adapter = self._selected_adapter()
        if adapter is None and not self.apply_all.get():
            self.app.show_toast("Select an active adapter first.", "warning")
            return
        provider_key = self.selected_provider.get()
        provider = DNS_PROVIDER_BY_KEY.get(provider_key)
        if provider is None:
            return
        apply_all = self.apply_all.get() and len(self._adapters) > 1
        self._applying = True
        self.apply_button.configure(text="Applying…", state="disabled")
        self.reset_button.configure(state="disabled")
        self.adapter_menu.configure(state="disabled")
        self.refresh_button.configure(state="disabled")
        target = "all active adapters" if apply_all else adapter.name

        def work() -> OperationResult:
            if apply_all:
                return self.app.services.dns_manager.apply_to_active(provider_key)
            assert adapter is not None
            return self.app.services.dns_manager.set_provider(adapter, provider_key)

        LOG.info("Applying %s DNS to %s", provider.name, target)
        self.app.run_task(
            "dns_apply",
            work,
            self._on_apply_done,
            self._on_apply_error,
            on_done=self._finish_apply,
        )

    def _finish_apply(self) -> None:
        self._applying = False
        self.apply_button.configure(text="Apply DNS", state="normal")
        self.reset_button.configure(state="normal")
        self.adapter_menu.configure(state="normal")
        self.refresh_button.configure(state="normal")
        self.refresh()
        self.app.refresh_security_pages()

    def _on_apply_done(self, result: OperationResult) -> None:
        kind = "success" if result.success else "error"
        self.app.show_toast(result.message, kind)
        for detail in result.details:
            LOG.info("DNS: %s", detail)

    def _on_apply_error(self, error: Exception) -> None:
        self.app.show_toast(f"DNS change failed: {error}", "error")
        LOG.error("DNS change failed: %s", error)

    def _reset_dhcp(self) -> None:
        adapter = self._selected_adapter()
        if adapter is None:
            self.app.show_toast("Select an active adapter first.", "warning")
            return
        self.reset_button.configure(state="disabled")
        self.apply_button.configure(state="disabled")
        LOG.info("Resetting DNS to DHCP on %s", adapter.name)
        self.app.run_task(
            "dns_reset",
            lambda: self.app.services.dns_manager.reset_to_dhcp(adapter),
            self._on_reset_done,
            self._on_apply_error,
            on_done=self._finish_apply,
        )

    def _on_reset_done(self, result: OperationResult) -> None:
        self.app.show_toast(result.message, "success" if result.success else "error")
        for detail in result.details:
            LOG.info("DNS reset: %s", detail)

    def on_show(self) -> None:
        self.refresh()
