# gui_widgets.py
# ============================================================================
# WidgetMixin — reusable CTk widget factory methods.
# Mix into any ctk.CTk subclass; no direct instantiation needed.
# ============================================================================

import customtkinter as ctk
from tkinter import filedialog

from utils.palette import (
    BG_CARD, BG_HEADER, BG_FRAME,
    ACCENT, ACCENT_HOVER, ACCENT2,
    TEXT_MAIN, TEXT_DIM, TEXT_BRIGHT, TEXT_SUBTLE,
    BORDER,
)


class WidgetMixin:
    """Factory helpers for consistently-styled CustomTkinter widgets."""

    # ── Layout helpers ────────────────────────────────────────────────────────

    def _styled_frame(self, parent, **kwargs):
        return ctk.CTkFrame(parent, fg_color=BG_FRAME, **kwargs)

    def _title_bar(self, parent, title_text, subtitle=None):
        bar = ctk.CTkFrame(parent, fg_color=BG_HEADER, corner_radius=0)
        bar.pack(fill="x")

        left = ctk.CTkFrame(bar, fg_color="transparent")
        left.pack(side="left", padx=20, pady=12)
        ctk.CTkLabel(
            left, text=title_text,
            font=("Courier Bold", 18), text_color=ACCENT2,
        ).pack(side="left")
        if subtitle:
            ctk.CTkLabel(
                left, text=f"  {subtitle}",
                font=("Courier", 11), text_color=TEXT_DIM,
            ).pack(side="left", padx=(8, 0))
        return bar

    def _section_label(self, parent, text, color=ACCENT2):
        ctk.CTkLabel(
            parent, text=text,
            font=("Courier Bold", 13), text_color=color,
        ).pack(anchor="w", padx=4, pady=(10, 4))

    # ── Widget factories ──────────────────────────────────────────────────────

    def _btn(self, parent, text, command, width=110, primary=True, **kwargs):
        fg    = ACCENT        if primary else BG_CARD
        hover = ACCENT_HOVER  if primary else "#1a2540"
        tc    = "#ffffff"     if primary else TEXT_SUBTLE
        return ctk.CTkButton(
            parent, text=text, width=width,
            fg_color=fg, hover_color=hover, text_color=tc,
            font=("Courier", 12),
            command=command, **kwargs,
        )

    def _checkbox(self, parent, text, variable, command):
        return ctk.CTkCheckBox(
            parent, text=text,
            variable=variable, command=command,
            text_color=TEXT_MAIN,
            fg_color=ACCENT, hover_color=ACCENT_HOVER,
            checkmark_color="#ffffff",
            border_color=BORDER,
            font=("Courier", 12),
        )

    def _entry(self, parent, placeholder):
        return ctk.CTkEntry(
            parent,
            placeholder_text=placeholder,
            fg_color=BG_CARD,
            border_color=BORDER,
            text_color=TEXT_BRIGHT,
            placeholder_text_color=TEXT_DIM,
            font=("Courier", 12),
        )

    # ── Compound widgets ──────────────────────────────────────────────────────

    def clickable_file_entry(self, parent, placeholder, is_file=False):
        """Entry + Browse button that opens a file-picker and writes the path."""
        frame = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=6)
        frame.pack(pady=5, fill="x")

        entry = self._entry(frame, placeholder)
        entry.pack(side="left", fill="x", expand=True, padx=(8, 5), pady=6)

        def open_picker():
            path = filedialog.askopenfilename() if is_file else filedialog.askdirectory()
            if path:
                entry.delete(0, "end")
                entry.insert(0, path)

        self._btn(frame, "Browse", open_picker, width=80).pack(side="right", padx=6, pady=6)
        return entry

    def checkbox_entry_row(self, parent, label, boolean_var, toggle_fn, placeholder):
        """
        Card row with a checkbox that reveals an entry when ticked.
        Returns (frame, checkbox_widget, entry_widget).
        """
        frame = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=6)
        frame.pack(fill="x", pady=5)

        cb = self._checkbox(frame, label, boolean_var, toggle_fn)
        cb.pack(side="left", padx=(10, 10), pady=8, anchor="w")

        entry = self._entry(frame, placeholder)
        entry.pack(side="left", fill="x", expand=True)
        entry.pack_forget()   # hidden until checkbox ticked

        return frame, cb, entry
