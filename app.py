"""
Context-Aware AI Vulnerability Risk Assessment System - Streamlit website.

Run with:   streamlit run app.py
"""

import streamlit as st

import db
import model
import ui

st.set_page_config(
    page_title="Vulnerability Risk Assessment",
    page_icon=":material/shield:",
    layout="wide",
)

db.init_db()
ui.inject_css()

if "user" not in st.session_state:
    st.session_state.user = None

user = st.session_state.user

if user is None:
    # Not logged in: the login page is the only page that exists.
    page = st.navigation(
        [st.Page("views/login.py", title="Log in", icon=":material/login:")],
        position="hidden",
    )
else:
    page = st.navigation([
        st.Page("views/assess.py", title="New assessment", icon=":material/edit_note:", default=True),
        st.Page("views/results.py", title="Results", icon=":material/monitoring:"),
        st.Page("views/about.py", title="About the system", icon=":material/info:"),
    ])
    with st.sidebar:
        st.markdown(f"**{user['org_name']}**")
        st.caption(f"{user['email']} · {user['business_type']}")
        if model.model_status() == "xgboost":
            st.success("XGBoost model connected", icon=":material/check_circle:")
        else:
            st.warning("Demo scoring: XGBoost model not connected yet",
                       icon=":material/science:")
        if st.button("Log out", icon=":material/logout:", width="stretch"):
            st.session_state.clear()
            st.rerun()

page.run()
