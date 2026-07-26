"""Shared visual system for the SOC dashboard."""

from typing import Any

import plotly.graph_objects as go
import streamlit as st

HONEYWELL_RED = "#e31b23"
NAVY = "#17243a"
SLATE = "#667085"
LIGHT_BLUE = "#3b82f6"
AMBER = "#f59e0b"
GREEN = "#16a34a"
SEVERITY_COLORS = {
    "critical": "#b42318",
    "high": "#e31b23",
    "medium": "#f59e0b",
    "low": "#3b82f6",
    "info": "#98a2b3",
}


def apply_theme() -> None:
    """Apply the light Honeywell-inspired visual language."""

    st.markdown(
        """
        <style>
        :root {
          --hw-red:#e31b23; --ink:#17202a; --muted:#667085;
          --canvas:#f5f7fa; --panel:#ffffff; --line:#e4e7ec;
        }
        .stApp { background:linear-gradient(135deg,#f7f9fc 0%,#eef2f7 100%); }
        [data-testid="stSidebar"] {
          background:#ffffff; border-right:1px solid var(--line);
          box-shadow:6px 0 24px rgba(16,24,40,.04);
        }
        [data-testid="stMetric"] {
          background:#fff; border:1px solid var(--line); border-radius:14px;
          padding:16px 18px; box-shadow:0 5px 18px rgba(16,24,40,.055);
        }
        [data-testid="stMetricLabel"] { color:var(--muted); }
        [data-testid="stMetricLabel"] p {
          white-space:normal !important; overflow:visible !important;
          text-overflow:clip !important; line-height:1.2; min-height:1.3rem;
        }
        [data-testid="stMetricValue"] {
          color:var(--ink); font-weight:720; overflow:visible !important;
        }
        [data-testid="stMetricValue"] > div {
          white-space:normal !important; overflow:visible !important;
          text-overflow:clip !important; word-break:break-word;
          font-size:clamp(1.55rem,2.2vw,2.35rem) !important; line-height:1.12;
        }
        [data-testid="stDataFrame"] {
          border:1px solid var(--line); border-radius:12px; overflow:hidden;
        }
        [data-testid="stPlotlyChart"] {
          background:#fff; border:1px solid var(--line); border-radius:14px;
          box-shadow:0 4px 14px rgba(16,24,40,.045); padding:6px;
        }
        .block-container { padding-top:1.6rem; max-width:1550px; }
        .hw-kicker { color:var(--hw-red); letter-spacing:.17em; font-weight:750; font-size:.72rem; }
        .hw-title { color:var(--ink); font-size:2.05rem; font-weight:780; margin:.15rem 0; }
        .hw-subtitle { color:var(--muted); margin-bottom:.4rem; }
        .hw-status {
          display:inline-flex; align-items:center; gap:.45rem; padding:.32rem .65rem;
          background:#ecfdf3; color:#067647; border:1px solid #abefc6;
          border-radius:999px; font-size:.76rem; font-weight:650;
        }
        .hw-dot { width:.48rem; height:.48rem; border-radius:50%; background:#12b76a; }
        .hw-section {
          font-size:1.15rem; font-weight:720; color:var(--ink); margin:.3rem 0 0;
        }
        .hw-section-sub { color:var(--muted); font-size:.86rem; margin-bottom:.75rem; }
        .hw-callout {
          background:#fff; border:1px solid var(--line); border-left:4px solid var(--hw-red);
          border-radius:12px; padding:.9rem 1rem; margin:.45rem 0;
        }
        [data-testid="stColumn"]:has(.copilot-marker) {
          position:sticky; top:1rem; align-self:flex-start;
          min-width:250px;
          max-height:calc(100vh - 2rem); overflow-y:auto;
          background:rgba(255,255,255,.96); border:1px solid var(--line);
          border-radius:16px; padding:1rem;
          box-shadow:0 12px 32px rgba(16,24,40,.10);
          scrollbar-width:thin;
        }
        .copilot-heading {
          display:flex; align-items:center; gap:.65rem; margin-bottom:.8rem;
          color:var(--ink); font-size:.96rem;
        }
        .copilot-heading small {
          display:block; color:var(--muted); font-size:.68rem; margin-top:.1rem;
        }
        .copilot-orb {
          display:grid; place-items:center; width:2.1rem; height:2.1rem;
          background:linear-gradient(135deg,#e31b23,#9b1118); color:#fff;
          border-radius:10px; box-shadow:0 5px 14px rgba(227,27,35,.24);
        }
        .copilot-risk {
          border:1px solid #fecdca; background:#fff6f5; border-radius:12px;
          padding:.75rem; margin:.2rem 0 .8rem;
        }
        .copilot-risk>span {
          color:#b42318; font-size:.65rem; letter-spacing:.11em; font-weight:760;
        }
        .copilot-risk>strong {
          display:block; color:#7a271a; font-size:1.7rem; line-height:1.1;
        }
        .copilot-risk>strong small { font-size:.78rem; font-weight:600; }
        .copilot-risk>p { color:var(--muted); font-size:.75rem; margin:.22rem 0 0; }
        .copilot-arrow { color:var(--hw-red); padding-left:.4rem; }
        @media (max-width: 900px) {
          [data-testid="stHorizontalBlock"]:has(.copilot-marker) {
            flex-direction:column;
          }
          [data-testid="stHorizontalBlock"]:has(.copilot-marker)
          > [data-testid="stColumn"] {
            width:100% !important; flex:1 1 100% !important;
          }
          [data-testid="stColumn"]:has(.copilot-marker) {
            position:static; min-width:0; max-height:none; overflow:visible;
          }
        }
        .stButton>button[kind="primary"] {
          background:var(--hw-red); border-color:var(--hw-red); border-radius:9px;
        }
        .stButton>button { border-radius:9px; }
        div[role="radiogroup"] label { padding:.28rem .15rem; }
        hr { border-color:var(--line); }
        </style>
        """,
        unsafe_allow_html=True,
    )


def page_header() -> None:
    """Render the product header and live system badge."""

    left, right = st.columns([5, 1])
    with left:
        st.markdown(
            '<div class="hw-kicker">SENTINELAI</div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div class="hw-title">SentinelAI</div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div class="hw-subtitle">AI-Powered Behavioral Threat Detection &amp; '
            "Investigation Platform</div>",
            unsafe_allow_html=True,
        )
    with right:
        st.markdown(
            '<div style="text-align:right;margin-top:1.2rem">'
            '<span class="hw-status"><span class="hw-dot"></span> SYSTEM ONLINE</span></div>',
            unsafe_allow_html=True,
        )


def section_header(title: str, subtitle: str) -> None:
    """Render a consistent section title and supporting context."""

    st.markdown(f'<div class="hw-section">{title}</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="hw-section-sub">{subtitle}</div>', unsafe_allow_html=True)


def chart(figure: go.Figure, *, height: int = 330, key: str | None = None) -> None:
    """Apply a clean light chart style and render the Plotly figure."""

    figure.update_layout(
        height=height,
        margin={"l": 20, "r": 20, "t": 58, "b": 24},
        paper_bgcolor="#ffffff",
        plot_bgcolor="#ffffff",
        font={"color": NAVY, "family": "Arial, sans-serif"},
        title_font={"size": 16, "color": NAVY},
        legend_title_text="",
        coloraxis_showscale=False,
        hoverlabel={"bgcolor": "#ffffff", "font_color": NAVY},
    )
    figure.update_xaxes(gridcolor="#eef1f5", linecolor="#d0d5dd")
    figure.update_yaxes(gridcolor="#eef1f5", linecolor="#d0d5dd")
    st.plotly_chart(
        figure,
        use_container_width=True,
        config={"displayModeBar": False, "responsive": True},
        key=key,
    )


def labelize(value: Any) -> str:
    """Convert machine identifiers into analyst-friendly labels."""

    return str(value).replace("_", " ").strip().title()
