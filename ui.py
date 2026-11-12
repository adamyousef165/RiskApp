"""Shared look-and-feel helpers."""

import html

import streamlit as st

LEVEL_ORDER = ["Critical", "High", "Medium", "Low"]

# text colour, background colour for each risk level
LEVEL_COLORS = {
    "Critical": ("#A32D2D", "#FCEBEB"),
    "High": ("#993C1D", "#FAECE7"),
    "Medium": ("#854F0B", "#FAEEDA"),
    "Low": ("#3B6D11", "#EAF3DE"),
}
CHART_COLORS = {"Critical": "#E24B4A", "High": "#D85A30", "Medium": "#EF9F27", "Low": "#639922"}


def inject_css() -> None:
    st.markdown("""
        <style>
        .risk-badge {display:inline-block; padding:4px 14px; border-radius:8px;
                     font-weight:600; font-size:1rem;}
        .risk-badge.small {padding:2px 10px; font-size:0.85rem;}
        .score-big {font-size:2rem; font-weight:600; margin-left:12px; vertical-align:middle;}
        .muted {opacity:0.75; font-size:0.9rem;}
        </style>
    """, unsafe_allow_html=True)


def badge(level: str, small: bool = False) -> str:
    fg, bg = LEVEL_COLORS.get(level, ("#444", "#eee"))
    cls = "risk-badge small" if small else "risk-badge"
    return f'<span class="{cls}" style="color:{fg};background:{bg}">{html.escape(level)}</span>'


def result_card(rec: dict, res: dict, rank: int | None = None) -> None:
    """The main output: risk level, score, why, and what to do."""
    with st.container(border=True):
        rank_text = f" · Priority rank #{rank}" if rank else ""
        system = f" · {html.escape(rec['system_name'])}" if rec.get("system_name") else ""
        st.markdown(
            f"{badge(res['risk_level'])}"
            f"<span class='score-big'>{res['risk_score']:.0f} / 100</span><br>"
            f"<span class='muted'>{html.escape(rec['cve_id'])} · CVSS {rec['cvss_score']}"
            f"{system}{rank_text}</span>",
            unsafe_allow_html=True,
        )
        st.progress(min(1.0, res["risk_score"] / 100))

        left, right = st.columns(2)
        with left:
            st.markdown("**Why this score**")
            if res["top_factors"]:
                top = max(p for _, p in res["top_factors"])
                for name, pts in res["top_factors"]:
                    st.markdown(f"<span class='muted'>{html.escape(name)}</span>",
                                unsafe_allow_html=True)
                    st.progress(pts / top, text=f"+{pts:g} points")
            else:
                st.caption("No significant risk factors.")
        with right:
            st.markdown("**Recommendation**")
            st.write(res["recommendation"])
            if rec.get("system_purpose"):
                st.markdown("**System purpose**")
                st.write(rec["system_purpose"])
            if rec.get("impact_description"):
                st.markdown("**Predicted impact (analyst note)**")
                st.write(rec["impact_description"])

        if res.get("source") != "xgboost":
            st.caption("Demo scoring (likelihood × impact formula). "
                       "Will be replaced by the trained XGBoost model.")
