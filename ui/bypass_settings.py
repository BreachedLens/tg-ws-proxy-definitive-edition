"""Bypass settings controls for the settings form."""
from __future__ import annotations

from ui.ctk_controls import create_entry, create_label, create_config_section, create_combobox
from ui.ctk_tooltip import attach_tooltip_to_widgets
from ui.i18n import t

_INNER_W = 396


class _BypassSettingsMixin:
    @staticmethod
    def _bypass_mode_labels():
        return {
            "alt_cdn": t("bypass.mode_alt_cdn"),
            "legacy": t("bypass.mode_legacy"),
        }

    @staticmethod
    def _create_bypass(ctk, frame, theme, cfg, default_config):
        from proxy.route_status import add_route_listener, get_active_route

        section = create_config_section(ctk, frame, theme, t("section.bypass"))
        labels = _BypassSettingsMixin._bypass_mode_labels()
        mode_value = cfg.get("bypass_mode", default_config.get("bypass_mode", "alt_cdn"))
        if mode_value not in labels:
            mode_value = "alt_cdn"
        mode_var = ctk.StringVar(master=frame, value=labels[mode_value])

        mode_label = create_label(ctk, section, theme, t("bypass.mode_label"), size=11)
        mode_label.pack(anchor="w", pady=(0, 2))
        mode_combo = create_combobox(
            ctk, section, theme, variable=mode_var, values=list(labels.values())
        )
        mode_combo.pack(fill="x", pady=(0, 6))

        cdn_fields = ctk.CTkFrame(section, fg_color="transparent")
        cdn_provider_label = create_label(
            ctk, cdn_fields, theme, t("bypass.cdn_provider"), size=11
        )
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
        custom_sni_entry = create_entry(
            ctk, custom_fields, theme, var=custom_sni_var, height=32, radius=8
        )
        custom_sni_entry.pack(fill="x", pady=(0, 4))
        custom_host_label = create_label(ctk, custom_fields, theme, t("bypass.custom_host"), size=11)
        custom_host_label.pack(anchor="w", pady=(0, 2))
        custom_host_entry = create_entry(
            ctk, custom_fields, theme, var=custom_host_var, height=32, radius=8
        )
        custom_host_entry.pack(fill="x", pady=(0, 4))
        custom_connect_ip_label = create_label(
            ctk, custom_fields, theme, t("bypass.custom_connect_ip"), size=11
        )
        custom_connect_ip_label.pack(anchor="w", pady=(0, 2))
        custom_connect_ip_entry = create_entry(
            ctk, custom_fields, theme, var=custom_connect_ip_var, height=32, radius=8
        )
        custom_connect_ip_entry.pack(fill="x", pady=(0, 4))

        status = create_label(ctk, section, theme, "", size=11, justify="left", wraplength=_INNER_W)
        status.pack(anchor="w")

        def selected_mode():
            return next((key for key, label in labels.items() if label == mode_var.get()), "alt_cdn")

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
            if selected_mode() == "alt_cdn":
                cdn_fields.pack(fill="x")
            else:
                cdn_fields.pack_forget()
            custom_fields.pack_forget()
            if selected_mode() == "alt_cdn" and selected_provider() == "custom":
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
            [mode_label, mode_combo, cdn_provider_label, provider_combo,
             custom_label, custom_sni_entry, custom_host_label, custom_host_entry,
             custom_connect_ip_label, custom_connect_ip_entry],
            t("bypass.settings_tip"),
        )
        return (
            mode_var, cdn_provider_var, custom_sni_var, custom_host_var,
            custom_connect_ip_var, status, route_changed,
        )
