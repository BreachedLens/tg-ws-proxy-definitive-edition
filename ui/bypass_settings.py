"""Bypass settings controls for the settings form."""
from __future__ import annotations

from typing import Any

from ui.ctk_controls import create_entry, create_checkbox, create_label, create_config_section, create_combobox
from ui.ctk_tooltip import attach_tooltip_to_widgets
from ui.i18n import t

_INNER_W = 396


class _BypassSettingsMixin:
    @staticmethod
    def _bypass_mode_labels():
        return {
            "alt_cdn": t("bypass.mode_alt_cdn"),
            "amneziawg": t("bypass.mode_amneziawg"),
            "legacy": t("bypass.mode_legacy"),
        }

    @staticmethod
    def _create_bypass(ctk, frame, theme, cfg, default_config):
        from proxy.route_status import add_route_listener, get_active_route

        section = create_config_section(ctk, frame, theme, t("section.bypass"))
        labels = _BypassSettingsMixin._bypass_mode_labels()
        mode_value = cfg.get("bypass_mode", default_config.get("bypass_mode", "alt_cdn"))
        if mode_value == "auto":
            mode_value = "alt_cdn"
        if mode_value == "amneziawg" and not cfg.get(
                "bypass_amneziawg_config_path", "").strip():
            mode_value = "alt_cdn"
        if mode_value not in labels:
            mode_value = "alt_cdn"
        mode_var = ctk.StringVar(master=frame, value=labels[mode_value])

        mode_label = create_label(ctk, section, theme, t("bypass.mode_label"), size=11)
        mode_label.pack(anchor="w", pady=(0, 2))
        mode_combo = create_combobox(ctk, section, theme, variable=mode_var, values=list(labels.values()))
        mode_combo.pack(fill="x", pady=(0, 6))

        awg_fields = ctk.CTkFrame(section, fg_color="transparent")
        awg_fields.pack(fill="x")
        cdn_fields = ctk.CTkFrame(section, fg_color="transparent")

        path_label = create_label(ctk, awg_fields, theme, t("bypass.config_path"), size=11)
        path_label.pack(anchor="w", pady=(0, 2))
        path_row = ctk.CTkFrame(awg_fields, fg_color="transparent")
        path_row.pack(fill="x", pady=(0, 4))
        path_var = ctk.StringVar(
            master=frame,
            value=str(cfg.get("bypass_amneziawg_config_path", default_config.get("bypass_amneziawg_config_path", ""))),
        )
        path_entry = create_entry(ctk, path_row, theme, var=path_var, height=32, radius=8)
        path_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))

        def browse_config():
            from tkinter import filedialog
            selected = filedialog.askopenfilename(
                parent=frame.winfo_toplevel(), title=t("bypass.choose_config"),
                filetypes=[(t("bypass.conf_files"), "*.conf"), (t("bypass.all_files"), "*.*")],
            )
            if selected:
                path_var.set(selected)

        browse_button = ctk.CTkButton(
            path_row, text=t("button.browse"), width=84, height=32,
            font=(theme.ui_font_family, 12), corner_radius=8,
            fg_color=theme.field_bg, hover_color=theme.field_border,
            text_color=theme.text_primary, border_width=1,
            border_color=theme.field_border, command=browse_config,
        )
        browse_button.pack(side="right")

        split_var = ctk.BooleanVar(master=frame, value=cfg.get("bypass_amneziawg_split_tunnel", True))
        split_checkbox = create_checkbox(ctk, awg_fields, theme, t("bypass.split_tunnel"), split_var)
        split_checkbox.pack(anchor="w", pady=(0, 4))

        dns_label = create_label(ctk, awg_fields, theme, t("bypass.dns_servers"), size=11)
        dns_label.pack(anchor="w", pady=(2, 2))
        dns_value = cfg.get("bypass_dns", default_config.get("bypass_dns", []))
        if isinstance(dns_value, (list, tuple)):
            dns_value = ", ".join(str(item) for item in dns_value)
        dns_var = ctk.StringVar(master=frame, value=str(dns_value))
        dns_entry = create_entry(ctk, awg_fields, theme, var=dns_var, height=32, radius=8)
        dns_entry.pack(fill="x", pady=(0, 2))
        dns_hint = create_label(ctk, awg_fields, theme, t("bypass.dns_hint"), size=10)
        dns_hint.pack(anchor="w", pady=(0, 6))

        cdn_provider_label = create_label(ctk, cdn_fields, theme, t("bypass.cdn_provider"), size=11)
        cdn_provider_label.pack(anchor="w", pady=(0, 2))
        from bypass.cdn import CDN_PROVIDER_IDS
        provider_names = {
            provider: t("bypass.provider_google" if provider == "google-gfe"
                        else "bypass.provider_" + provider)
            for provider in CDN_PROVIDER_IDS
        }
        provider = cfg.get(
            "bypass_cdn_provider",
            default_config.get("bypass_cdn_provider", "google-gfe"),
        )
        if provider not in provider_names:
            provider = "google-gfe"
        cdn_provider_var = ctk.StringVar(master=frame, value=provider_names[provider])
        provider_combo = create_combobox(
            ctk, cdn_fields, theme, variable=cdn_provider_var,
            values=[provider_names[key] for key in CDN_PROVIDER_IDS],
        )
        provider_combo.pack(fill="x", pady=(0, 4))

        custom_fields = ctk.CTkFrame(cdn_fields, fg_color="transparent")
        custom_sni_var = ctk.StringVar(master=frame, value=cfg.get("bypass_cdn_custom_sni", ""))
        custom_host_var = ctk.StringVar(master=frame, value=cfg.get("bypass_cdn_custom_host", ""))
        custom_connect_ip_var = ctk.StringVar(
            master=frame, value=cfg.get("bypass_cdn_custom_connect_ip", "")
        )
        custom_label = create_label(ctk, custom_fields, theme, t("bypass.custom_sni"), size=11)
        custom_label.pack(anchor="w", pady=(0, 2))
        custom_sni_entry = create_entry(ctk, custom_fields, theme, var=custom_sni_var, height=32, radius=8)
        custom_sni_entry.pack(fill="x", pady=(0, 4))
        custom_host_label = create_label(ctk, custom_fields, theme, t("bypass.custom_host"), size=11)
        custom_host_label.pack(anchor="w", pady=(0, 2))
        custom_host_entry = create_entry(ctk, custom_fields, theme, var=custom_host_var, height=32, radius=8)
        custom_host_entry.pack(fill="x", pady=(0, 4))
        custom_connect_ip_label = create_label(ctk, custom_fields, theme, t("bypass.custom_connect_ip"), size=11)
        custom_connect_ip_label.pack(anchor="w", pady=(0, 2))
        custom_connect_ip_entry = create_entry(
            ctk, custom_fields, theme, var=custom_connect_ip_var, height=32, radius=8
        )
        custom_connect_ip_entry.pack(fill="x", pady=(0, 4))

        status = create_label(ctk, section, theme, "", size=11, justify="left", wraplength=_INNER_W)
        status.pack(anchor="w")

        def selected_mode():
            return next((key for key, label in labels.items() if label == mode_var.get()), "amneziawg")

        def selected_provider():
            return next(
                (key for key, label in provider_names.items()
                 if label == cdn_provider_var.get()),
                "google-gfe",
            )

        def render_status(route):
            status.configure(text=(
                t("bypass.active_status", route=route) if route
                else t("bypass.status." + selected_mode())
            ))

        def update_visibility(*_):
            mode = selected_mode()
            if mode == "amneziawg":
                cdn_fields.pack_forget()
                awg_fields.pack(fill="x")
            elif mode == "alt_cdn":
                awg_fields.pack_forget()
                cdn_fields.pack(fill="x")
            else:
                awg_fields.pack_forget()
                cdn_fields.pack_forget()
            custom_fields.pack_forget()
            if selected_provider() == "custom":
                custom_fields.pack(fill="x")
            render_status(get_active_route())

        def route_changed(route):
            try:
                status.after(0, lambda: render_status(route))
            except Exception:
                pass

        mode_var.trace_add("write", update_visibility)
        cdn_provider_var.trace_add("write", update_visibility)
        add_route_listener(route_changed)
        update_visibility()
        attach_tooltip_to_widgets(
            [mode_label, mode_combo, path_label, path_entry, browse_button,
             split_checkbox, dns_label, dns_entry, dns_hint, cdn_provider_label,
             provider_combo, custom_label, custom_sni_entry, custom_host_label,
             custom_host_entry, custom_connect_ip_label, custom_connect_ip_entry],
            t("bypass.settings_tip"),
        )
        return (
            mode_var, path_var, split_var, dns_var, cdn_provider_var,
            custom_sni_var, custom_host_var, custom_connect_ip_var, status, route_changed,
        )
