"""Input page: organizational context + vulnerability data, by form or CSV."""

from pathlib import Path

import pandas as pd
import streamlit as st

import db
import model
import ui

user = st.session_state.user
O = model.OPTIONS
SAMPLE_CSV = Path(__file__).parent.parent / "sample_vulnerabilities.csv"
MAX_ROWS = 1000
MAX_BYTES = 10 * 1024 * 1024

# "Add to" choices: start a new assessment, or add to one of the user's existing ones.
NEW = 0
runs = db.list_runs(user["email"])
run_choices = [NEW] + [r["id"] for r in runs]
run_names = {NEW: "New assessment"}
run_names.update({r["id"]: f"#{r['id']} · {r['label']} ({r['n']} vulnerabilit"
                           f"{'y' if r['n'] == 1 else 'ies'})" for r in runs})


def save(rows: list, label: str, target: int) -> int:
    """Save to a new assessment or append to an existing one. Returns the run id."""
    if target != NEW and db.add_to_run(user["email"], target, rows):
        return target
    return db.save_run(user["email"], label, rows)


st.title("New risk assessment")
st.caption(f"Assessing for **{user['org_name']}**. Enter one vulnerability with the form, "
           "or upload a CSV to assess many at once.")

form_tab, csv_tab = st.tabs([":material/edit: Single vulnerability", ":material/upload: Upload CSV"])

# =========================================================================
# Single vulnerability form
# =========================================================================
with form_tab:
    with st.form("single"):
        st.subheader(":material/apartment: 1. Organizational context")
        st.caption("Describes the system the vulnerability is on.")
        c1, c2 = st.columns(2)
        with c1:
            system_name = st.text_input("System name", placeholder="Online banking portal")
            business_type = st.selectbox("Business type", O["business_type"],
                                         index=O["business_type"].index(user["business_type"]))
            system_criticality = st.selectbox("System criticality", O["system_criticality"], index=2)
            data_sensitivity = st.selectbox("Data sensitivity", O["data_sensitivity"], index=2)
            exposure_level = st.selectbox("Exposure level", O["exposure_level"], index=3)
        with c2:
            affected_users = st.number_input("Predicted number of affected users",
                                             min_value=0, max_value=10_000_000, value=1000, step=100)
            business_impact = st.selectbox("Business impact level", O["business_impact"], index=2)
            connected_systems = st.number_input("Number of connected systems",
                                                min_value=0, max_value=100, value=2)
            connected_system_criticality = st.selectbox("Criticality of connected systems",
                                                        O["connected_system_criticality"], index=2)
        related_assets = st.multiselect("Related assets", model.RELATED_ASSETS)
        system_purpose = st.text_area("System purpose (note only, not used for scoring)",
                                      placeholder="Student grades management system", height=68)
        impact_description = st.text_area(
            "Predicted scale of impact (note only, not used for scoring)",
            placeholder="Grade manipulation, user data leakage, service disruption…", height=68)

        st.divider()
        st.subheader(":material/bug_report: 2. Technical vulnerability data")
        c3, c4 = st.columns(2)
        with c3:
            cve_id = st.text_input("CVE ID", placeholder="CVE-2024-3400")
            cvss_score = st.slider("CVSS score", 0.0, 10.0, 7.5, step=0.1)
            attack_vector = st.selectbox("Attack vector", O["attack_vector"])
            attack_complexity = st.selectbox("Attack complexity", O["attack_complexity"])
            privileges_required = st.selectbox("Privileges required", O["privileges_required"])
        with c4:
            vulnerability_age_days = st.number_input("Vulnerability age (days since published)",
                                                     min_value=0, max_value=10000, value=30)
            exploit_available = st.toggle("Public exploit available")
            known_exploited = st.toggle("Known exploited (in CISA KEV)")
            patch_available = st.toggle("Patch available", value=True)
            user_interaction = st.toggle("User interaction required")

        st.divider()
        target = st.selectbox(
            "Add to", run_choices, format_func=run_names.get,
            help="Start a new assessment, or add this vulnerability to an existing one "
                 "so it's ranked together with the others.")
        submitted = st.form_submit_button("Predict risk", type="primary",
                                          icon=":material/insights:")

    if submitted:
        yn = lambda b: "Yes" if b else "No"
        rec, errors = model.validate({
            "cve_id": cve_id, "cvss_score": cvss_score,
            "vulnerability_age_days": vulnerability_age_days,
            "affected_users": affected_users, "connected_systems": connected_systems,
            "business_type": business_type, "system_criticality": system_criticality,
            "data_sensitivity": data_sensitivity, "exposure_level": exposure_level,
            "business_impact": business_impact,
            "connected_system_criticality": connected_system_criticality,
            "attack_vector": attack_vector, "attack_complexity": attack_complexity,
            "privileges_required": privileges_required,
            "user_interaction": yn(user_interaction), "exploit_available": yn(exploit_available),
            "known_exploited": yn(known_exploited), "patch_available": yn(patch_available),
            "related_assets": related_assets, "system_name": system_name,
            "system_purpose": system_purpose, "impact_description": impact_description,
        })
        if errors:
            for e in errors:
                st.error(e)
        else:
            res = model.predict(rec)
            run_id = save([(rec, res)], f"Manual · {rec['cve_id']}", target)
            st.session_state.selected_run = run_id
            st.subheader("Result")
            if target == NEW:
                st.caption(f"Saved as new assessment #{run_id}.")
            else:
                st.caption(f"Added to assessment #{run_id}. Open the results dashboard "
                           "to see how it ranks against the others.")
            ui.result_card(rec, res)
            st.page_link("views/results.py", label="Open in results dashboard",
                         icon=":material/monitoring:")

# =========================================================================
# CSV upload
# =========================================================================
with csv_tab:
    st.write("Each row is one vulnerability **plus** the organizational context of the "
             "system it's on. Column names and allowed values are listed below.")

    c1, c2 = st.columns([1, 1])
    with c1:
        st.download_button("Download sample CSV", SAMPLE_CSV.read_bytes(),
                           file_name="sample_vulnerabilities.csv", mime="text/csv",
                           icon=":material/download:")
    with c2:
        use_sample = st.button("Use the sample data", icon=":material/dataset:")

    uploaded = st.file_uploader("Upload vulnerability CSV (max 1000 rows, 10 MB)", type=["csv"])

    df = None
    if uploaded is not None:
        if uploaded.size > MAX_BYTES:
            st.error("File is larger than 10 MB.")
        else:
            try:
                df = pd.read_csv(uploaded, dtype=str, keep_default_na=False)
            except Exception:
                st.error("Couldn't read this file. Make sure it's a valid CSV.")
            source_label = f"CSV · {uploaded.name}"
    elif use_sample or st.session_state.get("using_sample"):
        st.session_state.using_sample = True
        df = pd.read_csv(SAMPLE_CSV, dtype=str, keep_default_na=False)
        source_label = "CSV · sample data"

    if df is not None:
        df.columns = [c.strip().lower() for c in df.columns]
        required = ["cve_id"] + list(model.NUMBERS) + list(model.OPTIONS)
        missing = [c for c in required if c not in df.columns]
        if missing:
            st.error("Missing columns: " + ", ".join(missing))
        elif len(df) > MAX_ROWS:
            st.error(f"The file has {len(df)} rows; the limit is {MAX_ROWS}.")
        elif len(df) == 0:
            st.error("The file has no rows.")
        else:
            valid, problems = [], []
            for i, row in df.iterrows():
                rec, errors = model.validate(row.to_dict())
                if errors:
                    problems.append({"row": i + 2, "cve_id": rec["cve_id"], "problem": "; ".join(errors)})
                else:
                    valid.append(rec)

            m1, m2, m3 = st.columns(3)
            m1.metric("Rows", len(df))
            m2.metric("Valid", len(valid))
            m3.metric("With errors", len(problems))
            st.markdown("**Preview**")
            st.dataframe(df.head(10), width="stretch", hide_index=True)
            if problems:
                st.warning("These rows will be skipped:")
                st.dataframe(pd.DataFrame(problems), width="stretch", hide_index=True)

            csv_target = st.selectbox("Add to", run_choices, format_func=run_names.get,
                                      key="csv_target") if valid else NEW
            if valid and st.button(f"Assess {len(valid)} vulnerabilities", type="primary",
                                   icon=":material/insights:"):
                rows = [(rec, model.predict(rec)) for rec in valid]
                st.session_state.selected_run = save(rows, source_label, csv_target)
                st.session_state.using_sample = False
                st.switch_page("views/results.py")

    with st.expander("CSV columns and allowed values"):
        st.markdown("""
| Column | Type | Allowed values |
|---|---|---|
| `cve_id` | text | `CVE-YYYY-NNNN` |
| `cvss_score` | number | 0 – 10 |
| `vulnerability_age_days` | number | 0 – 10000 |
| `affected_users` | number | 0 – 10,000,000 |
| `connected_systems` | number | 0 – 100 |
""" + "\n".join(f"| `{k}` | choice | {', '.join(v)} |" for k, v in O.items()) + """
| `related_assets` | optional, separated by `;` | """ + ", ".join(model.RELATED_ASSETS) + """ |
| `system_name`, `system_purpose`, `impact_description` | optional notes | free text |
""")
