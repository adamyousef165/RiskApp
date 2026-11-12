"""Login / create account page (the only page visible before logging in)."""

import streamlit as st

import db
import model

left, gap, right = st.columns([1.1, 0.15, 1])

with left:
    st.title(":material/shield: Context-Aware Vulnerability Risk Assessment")
    st.write(
        "Prioritize vulnerabilities by their **real risk to your organization**, "
        "not just their CVSS score."
    )
    st.markdown("""
        **How it works**
        1. Log in with your organization account
        2. Enter your system's organizational context and its vulnerabilities
           (form or CSV upload)
        3. Get a risk level, **Critical / High / Medium / Low**, with a 0-100 score,
           a priority rank, the reasons behind it, and a recommendation
    """)
    st.caption("Princess Sumaya University for Technology · Graduation project")

with right:
    login_tab, register_tab = st.tabs(["Log in", "Create account"])

    with login_tab:
        with st.form("login"):
            email = st.text_input("Email", placeholder="name@company.com")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Log in", type="primary",
                                              width="stretch")
        if submitted:
            user = db.check_login(email, password)
            if user:
                st.session_state.user = user
                st.rerun()
            else:
                st.error("Incorrect email or password.")

    with register_tab:
        with st.form("register"):
            org = st.text_input("Organization name", placeholder="Arab Bank - IT Security")
            btype = st.selectbox("Business type", model.OPTIONS["business_type"])
            new_email = st.text_input("Work email", placeholder="name@company.com")
            pw1 = st.text_input("Password (at least 8 characters)", type="password")
            pw2 = st.text_input("Confirm password", type="password")
            created = st.form_submit_button("Create account", type="primary",
                                            width="stretch")
        if created:
            if pw1 != pw2:
                st.error("Passwords don't match.")
            else:
                error = db.create_user(new_email, pw1, org, btype)
                if error:
                    st.error(error)
                else:
                    st.session_state.user = db.check_login(new_email, pw1)
                    st.rerun()
