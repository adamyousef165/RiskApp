"""About page: what the system does and what it uses."""

import streamlit as st

import model

st.title("About the system")
st.write(
    "This system helps cybersecurity analysts prioritize vulnerabilities by combining "
    "**technical vulnerability data** with **organizational context**. The same CVE can be "
    "Critical for a bank's internet-facing payment system and Low for an internal lab server."
)

st.subheader("Workflow")
st.graphviz_chart("""
digraph {
  rankdir=LR; node [shape=box, style="rounded,filled", fillcolor="#EEEDFE", color="#534AB7",
  fontname="Helvetica", fontsize=11];
  a [label="Login"]; b [label="Technical data\\n+ organizational context"];
  c [label="Validation &\\npreprocessing"]; d [label="Feature\\nengineering"];
  e [label="Risk model\\n(XGBoost)"]; f [label="Ranking &\\nrecommendations"];
  g [label="Dashboard"];
  a -> b -> c -> d -> e -> f -> g;
}
""")

c1, c2 = st.columns(2)
with c1:
    st.subheader("Technical factors")
    st.markdown("""
- CVE ID and CVSS score
- Attack vector, attack complexity, privileges required, user interaction
- Exploit availability and CISA KEV status
- Patch availability and vulnerability age
""")
with c2:
    st.subheader("Organizational factors")
    st.markdown("""
- Business type and business impact level
- System criticality and data sensitivity
- Exposure level and number of affected users
- Connected systems and their criticality
- Related assets
""")

st.subheader("Risk levels")
st.markdown("""
| Level | Score | Meaning |
|---|---|---|
| Critical | 75-100 | Remediate within 24-48 hours |
| High | 55-74 | Remediate within 7 days |
| Medium | 35-54 | Next patch cycle (30 days) |
| Low | 0-34 | Routine maintenance |
""")

if model.model_status() == "xgboost":
    st.success("Predictions come from the trained XGBoost model.")
else:
    st.info(
        "The current version uses a transparent placeholder formula "
        "(likelihood × impact). It will be replaced by the trained XGBoost model; "
        "the inputs and outputs of the website stay the same."
    )
