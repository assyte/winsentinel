"""Reusable CustomTkinter components for the WinSentinel interface."""

from __future__ import annotations

import math
import queue
import tkinter as tk
from datetime import datetime
from typing import Callable

import customtkinter as ctk

from core.constants import (
    APP_NAME,
    APP_VERSION,
    CHECK_ICONS,
    COLORS,
    FONT_MONO,
    STATUS_META,
)
from core.logger import LOG_QUEUE, get_log_path
from core.models import Finding, Status
from ui.theme import (
    danger_button_kwargs,
    display_font,
    ghost_button_kwargs,
    mono_font,
    primary_button_kwargs,
    secondary_button_kwargs,
    ui_font,
)


def status_color(status: Status | str) -> str:
    key = status.value if isinstance(status, Status) else status
    return STATUS_META.get(key, STATUS_META["unknown"])["color"]


def status_soft(status: Status | str) -> str:
    key = status.value if isinstance(status, Status) else status
    return STATUS_META.get(key, STATUS_META["unknown"])["soft"]


class Card(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        defaults = {
            "fg_color": COLORS["card"],
            "corner_radius": 10,
            "border_width": 1,
            "border_color": COLORS["border"],
        }
        defaults.update(kwargs)
        super().__init__(master, **defaults)


class StatusPill(ctk.CTkFrame):
    def __init__(self, master, status: Status | str = Status.INFO, **kwargs):
        super().__init__(
            master,
            fg_color=status_soft(status),
            corner_radius=99,
            height=22,
            **kwargs,
        )
        self._dot = ctk.CTkLabel(
            self,
            text="●",
            font=ui_font(8),
            text_color=status_color(status),
            width=9,
        )
        self._dot.grid(row=0, column=0, padx=(8, 3), pady=4)
        self._label = ctk.CTkLabel(
            self,
            text=STATUS_META[status.value if isinstance(status, Status) else status]["label"],
            font=ui_font(9, "bold"),
            text_color=status_color(status),
            height=16,
        )
        self._label.grid(row=0, column=1, padx=(0, 9), pady=3)

    def set_status(self, status: Status | str) -> None:
        key = status.value if isinstance(status, Status) else status
        meta = STATUS_META.get(key, STATUS_META["unknown"])
        self.configure(fg_color=meta["soft"])
        self._dot.configure(text_color=meta["color"])
        self._label.configure(text=meta["label"], text_color=meta["color"])

    def set_text(self, text: str) -> None:
        self._label.configure(text=text)


class Sidebar(ctk.CTkFrame):
    NAV_ITEMS = (
        ("dashboard", "◈", "Dashboard"),
        ("network", "◎", "DNS & Network"),
        ("firewall", "⬡", "Firewall & Defender"),
        ("privacy", "◐", "Browser & Privacy"),
        ("tools", "◇", "Security Tools"),
    )

    def __init__(self, master, on_navigate: Callable[[str], None], **kwargs):
        super().__init__(
            master,
            width=196,
            corner_radius=0,
            fg_color=COLORS["sidebar"],
            **kwargs,
        )
        self.grid_propagate(False)
        self._on_navigate = on_navigate
        self._buttons: dict[str, ctk.CTkButton] = {}
        self._bars: dict[str, ctk.CTkFrame] = {}
        self._active = "dashboard"

        self._build_brand()
        self._build_nav()
        self._build_footer()

    def _build_brand(self) -> None:
        brand = ctk.CTkFrame(self, fg_color="transparent")
        brand.pack(fill="x", padx=16, pady=(18, 22))

        canvas = tk.Canvas(
            brand,
            width=28,
            height=34,
            bg=COLORS["sidebar"],
            highlightthickness=0,
        )
        canvas.pack(side="left", padx=(0, 9))
        canvas.create_polygon(
            (14, 1, 26, 6, 26, 18, 14, 32, 2, 18, 2, 6),
            fill=COLORS["accent"],
            outline="",
        )
        canvas.create_polygon(
            (14, 7, 21, 10, 21, 17, 14, 25, 7, 17, 7, 10),
            fill="#032a31",
            outline="",
        )
        canvas.create_text(
            14,
            14,
            text="✓",
            fill=COLORS["accent"],
            font=(FONT_MONO, 10, "bold"),
        )

        labels = ctk.CTkFrame(brand, fg_color="transparent")
        labels.pack(side="left", fill="y")
        ctk.CTkLabel(
            labels,
            text=APP_NAME,
            font=display_font(15, "bold"),
            text_color=COLORS["text"],
            anchor="w",
        ).pack(anchor="w", pady=(1, 0))
        ctk.CTkLabel(
            labels,
            text="WINDOWS SECURITY",
            font=ui_font(7, "bold"),
            text_color=COLORS["text_dim"],
            anchor="w",
        ).pack(anchor="w")

    def _build_nav(self) -> None:
        for key, icon, label in self.NAV_ITEMS:
            row = ctk.CTkFrame(self, fg_color="transparent", height=38)
            row.pack(fill="x", padx=8, pady=1)
            row.pack_propagate(False)
            bar = ctk.CTkFrame(
                row,
                width=2,
                height=20,
                corner_radius=1,
                fg_color="transparent",
            )
            bar.pack(side="left", padx=(0, 4))
            button = ctk.CTkButton(
                row,
                text=f"{icon}   {label}",
                anchor="w",
                height=34,
                corner_radius=8,
                fg_color="transparent",
                hover_color=COLORS["card_hover"],
                text_color=COLORS["text_muted"],
                font=ui_font(11),
                command=lambda name=key: self._select(name),
            )
            button.pack(side="left", fill="both", expand=True)
            self._buttons[key] = button
            self._bars[key] = bar
        self._apply_active()

    def _build_footer(self) -> None:
        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.pack(side="bottom", fill="x", padx=10, pady=12)

        self._status_card = ctk.CTkFrame(
            footer,
            fg_color=COLORS["card_muted"],
            corner_radius=8,
            border_width=1,
            border_color=COLORS["border"],
        )
        self._status_card.pack(fill="x", pady=(0, 8))

        status_top = ctk.CTkFrame(self._status_card, fg_color="transparent")
        status_top.pack(fill="x", padx=10, pady=(7, 1))
        self._status_dot = ctk.CTkLabel(
            status_top,
            text="●",
            font=ui_font(8),
            text_color=COLORS["success"],
            width=10,
        )
        self._status_dot.pack(side="left")
        self._status_label = ctk.CTkLabel(
            status_top,
            text="READY",
            font=ui_font(9, "bold"),
            text_color=COLORS["text"],
        )
        self._status_label.pack(side="left")

        self._status_detail = ctk.CTkLabel(
            self._status_card,
            text="Scanning on startup",
            font=ui_font(8),
            text_color=COLORS["text_dim"],
            anchor="w",
            wraplength=156,
            justify="left",
        )
        self._status_detail.pack(fill="x", padx=10, pady=(0, 7))

        admin_row = ctk.CTkFrame(footer, fg_color="transparent")
        admin_row.pack(fill="x", padx=2)
        self._admin_dot = ctk.CTkLabel(
            admin_row,
            text="●",
            font=ui_font(7),
            text_color=COLORS["text_dim"],
            width=10,
        )
        self._admin_dot.pack(side="left")
        self._admin_label = ctk.CTkLabel(
            admin_row,
            text="CHECKING",
            font=ui_font(8, "bold"),
            text_color=COLORS["text_dim"],
            anchor="w",
        )
        self._admin_label.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(
            admin_row,
            text=f"v{APP_VERSION}",
            font=ui_font(8),
            text_color=COLORS["text_dim"],
        ).pack(side="right")

    def _select(self, key: str) -> None:
        self._active = key
        self._apply_active()
        self._on_navigate(key)

    def _apply_active(self) -> None:
        for key, button in self._buttons.items():
            selected = key == self._active
            button.configure(
                fg_color=COLORS["accent_soft"] if selected else "transparent",
                text_color=COLORS["accent"] if selected else COLORS["text_muted"],
                font=ui_font(11, "bold" if selected else "normal"),
            )
            self._bars[key].configure(
                fg_color=COLORS["accent"] if selected else "transparent"
            )

    def set_status(self, text: str, detail: str = "", color: str | None = None) -> None:
        self._status_label.configure(text=text.upper())
        self._status_detail.configure(text=detail)
        self._status_dot.configure(text_color=color or COLORS["success"])

    def set_admin(self, elevated: bool) -> None:
        if elevated:
            self._admin_dot.configure(text_color=COLORS["success"])
            self._admin_label.configure(
                text="ADMINISTRATOR",
                text_color=COLORS["success"],
            )
        else:
            self._admin_dot.configure(text_color=COLORS["warning"])
            self._admin_label.configure(
                text="LIMITED USER",
                text_color=COLORS["warning"],
            )


class PageHeader(ctk.CTkFrame):
    def __init__(self, master, title: str, subtitle: str, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.grid_columnconfigure(0, weight=1)
        text = ctk.CTkFrame(self, fg_color="transparent")
        text.grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            text,
            text=title,
            font=display_font(20, "bold"),
            text_color=COLORS["text"],
            anchor="w",
        ).pack(anchor="w")
        ctk.CTkLabel(
            text,
            text=subtitle,
            font=ui_font(10),
            text_color=COLORS["text_muted"],
            anchor="w",
        ).pack(anchor="w", pady=(1, 0))
        self.actions = ctk.CTkFrame(self, fg_color="transparent", width=1, height=1)
        self.actions.grid(row=0, column=1, sticky="e")

    def add(self, widget: ctk.CTkBaseClass) -> None:
        widget.pack(side="left", padx=(6, 0))


class SectionLabel(ctk.CTkFrame):
    def __init__(self, master, title: str, subtitle: str = "", **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        ctk.CTkLabel(
            self,
            text=title,
            font=ui_font(13, "bold"),
            text_color=COLORS["text"],
            anchor="w",
        ).pack(anchor="w")
        if subtitle:
            ctk.CTkLabel(
                self,
                text=subtitle,
                font=ui_font(9),
                text_color=COLORS["text_dim"],
                anchor="w",
            ).pack(anchor="w", pady=(1, 0))


class InfoBanner(ctk.CTkFrame):
    def __init__(
        self,
        master,
        text: str,
        *,
        accent: str = COLORS["warning"],
        glyph: str = "!",
        **kwargs,
    ):
        if accent == COLORS["warning"]:
            soft = COLORS["warning_soft"]
        elif accent == COLORS["info"]:
            soft = COLORS["info_soft"]
        elif accent == COLORS["danger"]:
            soft = COLORS["danger_soft"]
        else:
            soft = COLORS["accent_soft"]
        super().__init__(
            master,
            fg_color=soft,
            corner_radius=8,
            border_width=1,
            border_color=COLORS["border"],
            **kwargs,
        )
        ctk.CTkLabel(
            self,
            text=glyph,
            width=22,
            height=22,
            corner_radius=11,
            fg_color=accent,
            text_color="#000000",
            font=ui_font(10, "bold"),
        ).pack(side="left", padx=(10, 8), pady=8)
        self.label = ctk.CTkLabel(
            self,
            text=text,
            font=ui_font(9),
            text_color=COLORS["text"],
            anchor="w",
            justify="left",
            wraplength=690,
        )
        self.label.pack(side="left", fill="x", expand=True, padx=(0, 10), pady=8)


class ScoreGauge(tk.Canvas):
    def __init__(self, master, size: int = 136, **kwargs):
        self.size = size
        super().__init__(
            master,
            width=size,
            height=size,
            bg=COLORS["card"],
            highlightthickness=0,
            **kwargs,
        )
        self._score = 0
        self._target = 0
        self._job: str | None = None
        self._draw(0)

    def set_score(self, score: int, animate: bool = True) -> None:
        score = max(0, min(100, int(score)))
        self._target = score
        if self._job:
            try:
                self.after_cancel(self._job)
            except Exception:
                pass
            self._job = None
        if not animate:
            self._score = score
            self._draw(score)
            return
        self._animate()

    def _animate(self) -> None:
        if not self.winfo_exists():
            return
        distance = self._target - self._score
        if abs(distance) <= 1:
            self._score = self._target
            self._draw(self._score)
            self._job = None
            return
        step = max(1, math.ceil(abs(distance) / 7))
        self._score += step if distance > 0 else -step
        self._draw(self._score)
        self._job = self.after(18, self._animate)

    def _color(self, score: int) -> str:
        if score >= 80:
            return COLORS["success"]
        if score >= 55:
            return COLORS["warning"]
        return COLORS["danger"]

    def _draw(self, score: int) -> None:
        self.delete("all")
        margin = 11
        width = 8
        box = (margin, margin, self.size - margin, self.size - margin)
        self.create_oval(*box, outline=COLORS["border"], width=width)
        if score > 0:
            self.create_arc(
                *box,
                start=90,
                extent=-359.9 * (score / 100),
                style="arc",
                outline=self._color(score),
                width=width,
            )
        # A tiny accent tick at the top makes the gauge feel intentional.
        self.create_oval(
            self.size / 2 - 1.5,
            margin - 2,
            self.size / 2 + 1.5,
            margin + 1,
            fill=COLORS["bg"],
            outline=COLORS["bg"],
        )
        self.create_text(
            self.size / 2,
            self.size / 2 - 13,
            text=str(score),
            fill=COLORS["text"],
            font=(FONT_MONO, max(22, int(self.size * 0.24)), "bold"),
        )
        self.create_text(
            self.size / 2,
            self.size / 2 + 14,
            text="SECURITY SCORE",
            fill=COLORS["text_dim"],
            font=("Segoe UI", 6, "bold"),
        )
        self.create_text(
            self.size / 2,
            self.size / 2 + 28,
            text="/ 100",
            fill=self._color(score),
            font=("Segoe UI", 8, "bold"),
        )


class MiniMetric(ctk.CTkFrame):
    def __init__(
        self,
        master,
        label: str,
        value: str = "—",
        color: str = COLORS["text"],
        **kwargs,
    ):
        super().__init__(
            master,
            fg_color=COLORS["card_muted"],
            corner_radius=8,
            border_width=1,
            border_color=COLORS["border"],
            **kwargs,
        )
        self._value = ctk.CTkLabel(
            self,
            text=value,
            font=mono_font(14, "bold"),
            text_color=color,
            anchor="w",
        )
        self._value.pack(anchor="w", padx=8, pady=(4, 0))
        self._label = ctk.CTkLabel(
            self,
            text=label.upper(),
            font=ui_font(6, "bold"),
            text_color=COLORS["text_dim"],
            anchor="w",
        )
        self._label.pack(anchor="w", padx=8, pady=(0, 4))

    def set(self, value: str, color: str | None = None) -> None:
        self._value.configure(text=value)
        if color:
            self._value.configure(text_color=color)


def _shorten(text: str, limit: int) -> str:
    value = " ".join(str(text).split())
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "…"


class FindingCard(Card):
    def __init__(self, master, finding: Finding, **kwargs):
        super().__init__(master, **kwargs)
        self._finding = finding
        self.grid_columnconfigure(1, weight=1)

        tile = ctk.CTkLabel(
            self,
            text=CHECK_ICONS.get(finding.key, "SEC"),
            width=38,
            height=32,
            corner_radius=7,
            fg_color=status_soft(finding.status),
            text_color=status_color(finding.status),
            font=mono_font(8, "bold"),
        )
        tile.grid(row=0, column=0, padx=(11, 8), pady=(10, 0), sticky="nw")

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=1, columnspan=2, sticky="ew", padx=(0, 11), pady=(9, 0))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            header,
            text=finding.title,
            font=ui_font(11, "bold"),
            text_color=COLORS["text"],
            anchor="w",
        ).grid(row=0, column=0, sticky="w")
        pill = StatusPill(header, finding.status)
        pill.grid(row=0, column=1, sticky="e")

        ctk.CTkLabel(
            self,
            text=_shorten(finding.summary, 110),
            font=ui_font(9),
            text_color=COLORS["text_muted"],
            anchor="w",
            justify="left",
            wraplength=300,
        ).grid(row=1, column=1, columnspan=2, sticky="w", padx=(0, 11), pady=(2, 0))

        self.grid_rowconfigure(2, minsize=9)


class LogConsole(ctk.CTkFrame):
    MAX_LINES = 1500

    def __init__(self, master, **kwargs):
        super().__init__(
            master,
            fg_color=COLORS["card"],
            corner_radius=10,
            border_width=1,
            border_color=COLORS["border"],
            **kwargs,
        )
        self._collapsed = True
        self._poll_job: str | None = None
        self._build_header()
        self._build_body()
        self._body.pack_forget()
        self._toggle_button.configure(text="Show  ▴")
        self._insert(
            "system",
            f"WinSentinel v{APP_VERSION} console ready · "
            f"{'log: ' + str(get_log_path()) if get_log_path() else 'file logging unavailable'}",
        )
        self._poll()

    def _build_header(self) -> None:
        header = ctk.CTkFrame(self, fg_color="transparent", height=30)
        header.pack(fill="x", padx=10, pady=(2, 0))
        header.pack_propagate(False)
        ctk.CTkLabel(
            header,
            text="●",
            font=ui_font(7),
            text_color=COLORS["success"],
            width=10,
        ).pack(side="left")
        ctk.CTkLabel(
            header,
            text="SYSTEM LOG",
            font=ui_font(8, "bold"),
            text_color=COLORS["text_muted"],
        ).pack(side="left")
        self._summary = ctk.CTkLabel(
            header,
            text="live output",
            font=ui_font(8),
            text_color=COLORS["text_dim"],
        )
        self._summary.pack(side="left", padx=(8, 0))
        self._toggle_button = ctk.CTkButton(
            header,
            text="Show  ▴",
            width=60,
            command=self.toggle,
            **ghost_button_kwargs(compact=True),
        )
        self._toggle_button.pack(side="right")
        ctk.CTkButton(
            header,
            text="Clear",
            width=44,
            command=self.clear,
            **ghost_button_kwargs(compact=True),
        ).pack(side="right", padx=(0, 2))

    def _build_body(self) -> None:
        self._body = ctk.CTkFrame(self, fg_color="transparent", height=120)
        self._body.pack(fill="both", expand=True, padx=10, pady=(2, 8))
        self._body.pack_propagate(False)

        text_frame = tk.Frame(self._body, bg=COLORS["input"], highlightthickness=0)
        text_frame.pack(side="left", fill="both", expand=True)
        self._text = tk.Text(
            text_frame,
            bg=COLORS["input"],
            fg=COLORS["text_muted"],
            relief="flat",
            borderwidth=0,
            highlightthickness=0,
            wrap="word",
            font=(FONT_MONO, 8),
            padx=9,
            pady=6,
            insertbackground=COLORS["accent"],
            selectbackground="#164e63",
            spacing1=1,
            spacing3=1,
            state="disabled",
        )
        scrollbar = ctk.CTkScrollbar(
            text_frame,
            command=self._text.yview,
            button_color=COLORS["border_bright"],
            button_hover_color=COLORS["text_dim"],
            fg_color=COLORS["input"],
        )
        scrollbar.pack(side="right", fill="y")
        self._text.configure(yscrollcommand=scrollbar.set)
        self._text.pack(side="left", fill="both", expand=True)

        self._text.tag_configure("timestamp", foreground=COLORS["text_dim"])
        self._text.tag_configure("INFO", foreground=COLORS["text_muted"])
        self._text.tag_configure("SUCCESS", foreground=COLORS["success"])
        self._text.tag_configure("WARNING", foreground=COLORS["warning"])
        self._text.tag_configure("ERROR", foreground=COLORS["danger"])
        self._text.tag_configure("DEBUG", foreground=COLORS["text_dim"])
        self._text.tag_configure("system", foreground=COLORS["accent"])

    def _poll(self) -> None:
        if not self.winfo_exists():
            return
        drained = 0
        while drained < 80:
            try:
                record = LOG_QUEUE.get_nowait()
            except queue.Empty:
                break
            drained += 1
            message = record.getMessage()
            level = record.levelname.upper()
            if level not in {"INFO", "WARNING", "ERROR", "DEBUG"}:
                level = "INFO"
            timestamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
            self._insert(level, message, timestamp)
        self._poll_job = self.after(140, self._poll)

    def _insert(self, level: str, message: str, timestamp: str | None = None) -> None:
        if not hasattr(self, "_text"):
            return
        at_bottom = self._text.yview()[1] >= 0.999
        self._text.configure(state="normal")
        if timestamp:
            self._text.insert("end", f"{timestamp} ", "timestamp")
        prefix = f"{level:<7} "
        if level == "system":
            prefix = "SYSTEM  "
        self._text.insert("end", prefix, level if level in ("WARNING", "ERROR", "DEBUG", "SUCCESS", "system") else "INFO")
        self._text.insert("end", message.replace("\n", "\n         ") + "\n", level if level in ("WARNING", "ERROR", "DEBUG", "SUCCESS") else "INFO")
        lines = int(float(self._text.index("end-1c").split(".")[0]))
        if lines > self.MAX_LINES:
            self._text.delete("1.0", f"{lines - self.MAX_LINES}.0")
        self._text.configure(state="disabled")
        if at_bottom:
            self._text.see("end")

    def toggle(self) -> None:
        self._collapsed = not self._collapsed
        if self._collapsed:
            self._body.pack_forget()
            self._toggle_button.configure(text="Show  ▴")
        else:
            self._body.pack(fill="both", expand=True, padx=10, pady=(2, 8))
            self._toggle_button.configure(text="Hide  ▾")
            self._text.see("end")

    def clear(self) -> None:
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._text.configure(state="disabled")

    def destroy(self) -> None:
        if self._poll_job:
            try:
                self.after_cancel(self._poll_job)
            except Exception:
                pass
        super().destroy()


class ConfirmDialog(ctk.CTkToplevel):
    """A small modal confirmation window matching the application theme."""

    def __init__(
        self,
        parent,
        *,
        title: str,
        message: str,
        confirm_text: str = "Confirm",
        danger: bool = False,
        on_confirm: Callable[[], None] | None = None,
    ):
        super().__init__(parent)
        self._on_confirm = on_confirm
        self.overrideredirect(True)
        self.configure(fg_color=COLORS["bg"])
        self.attributes("-topmost", True)
        self._width = 440
        self._height = 238
        self._center(parent)
        self._build(title, message, confirm_text, danger)
        self.bind("<Escape>", lambda _event: self._close())
        self.after(60, self._grab)

    def _center(self, parent) -> None:
        parent.update_idletasks()
        x = parent.winfo_rootx() + max(0, (parent.winfo_width() - self._width) // 2)
        y = parent.winfo_rooty() + max(0, (parent.winfo_height() - self._height) // 2)
        self.geometry(f"{self._width}x{self._height}+{x}+{y}")

    def _grab(self) -> None:
        try:
            self.grab_set()
            self.focus_force()
        except Exception:
            pass

    def _build(self, title: str, message: str, confirm_text: str, danger: bool) -> None:
        shell = ctk.CTkFrame(
            self,
            fg_color=COLORS["card"],
            corner_radius=12,
            border_width=1,
            border_color=COLORS["border_bright"],
        )
        shell.pack(fill="both", expand=True, padx=1, pady=1)

        top = ctk.CTkFrame(shell, fg_color="transparent")
        top.pack(fill="x", padx=18, pady=(18, 0))
        accent = COLORS["danger"] if danger else COLORS["accent"]
        ctk.CTkLabel(
            top,
            text="!" if danger else "?",
            width=32,
            height=32,
            corner_radius=16,
            fg_color=COLORS["danger_soft"] if danger else COLORS["accent_soft"],
            text_color=accent,
            font=ui_font(14, "bold"),
        ).pack(side="left", padx=(0, 11))
        ctk.CTkLabel(
            top,
            text=title,
            font=ui_font(15, "bold"),
            text_color=COLORS["text"],
            anchor="w",
        ).pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(
            shell,
            text=message,
            font=ui_font(10),
            text_color=COLORS["text_muted"],
            justify="left",
            anchor="w",
            wraplength=384,
        ).pack(fill="x", padx=20, pady=(12, 0))

        buttons = ctk.CTkFrame(shell, fg_color="transparent")
        buttons.pack(side="bottom", fill="x", padx=18, pady=16)
        ctk.CTkButton(
            buttons,
            text="Cancel",
            width=82,
            command=self._close,
            **secondary_button_kwargs(compact=True),
        ).pack(side="right")
        ctk.CTkButton(
            buttons,
            text=confirm_text,
            width=120,
            command=self._confirm,
            **(danger_button_kwargs(compact=True) if danger else primary_button_kwargs(compact=True)),
        ).pack(side="right", padx=(0, 8))

    def _confirm(self) -> None:
        callback = self._on_confirm
        self._close()
        if callback:
            callback()

    def _close(self) -> None:
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()


def make_primary_button(master, text: str, command: Callable, **kwargs) -> ctk.CTkButton:
    options = primary_button_kwargs(compact=kwargs.pop("compact", False))
    options.update(kwargs)
    return ctk.CTkButton(master, text=text, command=command, **options)


def make_secondary_button(master, text: str, command: Callable, **kwargs) -> ctk.CTkButton:
    options = secondary_button_kwargs(compact=kwargs.pop("compact", False))
    options.update(kwargs)
    return ctk.CTkButton(master, text=text, command=command, **options)
