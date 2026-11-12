"""Results dashboard: ranked risks, charts, CVSS comparison, details."""

import altair as alt
import pandas as pd
import streamlit as st

import db
import ui

user = st.session_state.user

st.title("Risk results")

runs = db.list_runs(user["email"])
if not runs:
    st.info("No assessments yet. Enter a vulnerability or upload a CSV to see results here.")
    st.page_link("views/assess.py", label="Start a new assessment", icon=":material/edit_note:")
    st.stop()

# ----------------------------------------------------------- pick a run ---
ALL = 0  # special choice: every vulnerability across all assessments
total = sum(r["n"] for r in runs)
run_ids = [ALL] + [r["id"] for r in runs]
labels = {ALL: f"All vulnerabilities · whole organization ({total} across {len(runs)} "
               f"assessment{'' if len(runs) == 1 else 's'})"}
labels.update({r["id"]: f"#{r['id']} · {r['created_at'].replace('T', ' ')} · {r['label']} "
                        f"({r['n']} vulnerabilit{'y' if r['n'] == 1 else 'ies'})" for r in runs})
default = st.session_state.get("selected_run")
index = run_ids.index(default) if default in run_ids else 1
run_id = st.selectbox("Assessment", run_ids, index=index, format_func=labels.get)
st.session_state.selected_run = run_id
show_all = run_id == ALL

rows = db.load_all(user["email"]) if show_all else db.load_run(user["email"], run_id)
if not rows:
    st.warning("This assessment is empty.")
    st.stop()
if show_all:
    st.caption("Every vulnerability your organization has assessed, ranked together. "
               "If the same CVE was assessed more than once, each entry is listed.")

# Rank by context-aware risk score (and by CVSS alone, for comparison).
table = pd.DataFrame([{
    "CVE": rec["cve_id"],
    "System": rec.get("system_name") or "-",
    "Risk level": res["risk_level"],
    "Risk score": res["risk_score"],
    "CVSS": rec["cvss_score"],
    "Exposure": rec["exposure_level"],
    "Criticality": rec["system_criticality"],
    "Exploit": rec["exploit_available"],
    "KEV": rec["known_exploited"],
    "Patch": rec["patch_available"],
    "Assessment": f"#{rid}",
} for rec, res, rid in rows])
if not show_all:
    table = table.drop(columns=["Assessment"])
table["_i"] = range(len(table))
table = table.sort_values(["Risk score", "CVSS"], ascending=False)
table.insert(0, "Rank", range(1, len(table) + 1))
table["CVSS rank"] = table["CVSS"].rank(ascending=False, method="min").astype(int)

# ------------------------------------------------------------- summary ---
counts = table["Risk level"].value_counts()
cols = st.columns(5)
cols[0].metric("Vulnerabilities", len(table))
for col, level in zip(cols[1:], ui.LEVEL_ORDER):
    col.metric(level, int(counts.get(level, 0)))

chart_col, compare_col = st.columns([1, 1.3])

with chart_col:
    st.subheader("Risk distribution")
    dist = pd.DataFrame({"Risk level": ui.LEVEL_ORDER,
                         "Count": [int(counts.get(l, 0)) for l in ui.LEVEL_ORDER]})
    st.altair_chart(
        alt.Chart(dist).mark_bar(cornerRadiusEnd=4).encode(
            x=alt.X("Count:Q", axis=alt.Axis(tickMinStep=1)),
            y=alt.Y("Risk level:N", sort=ui.LEVEL_ORDER, title=None),
            color=alt.Color("Risk level:N", legend=None,
                            scale=alt.Scale(domain=list(ui.CHART_COLORS),
                                            range=list(ui.CHART_COLORS.values()))),
            tooltip=["Risk level", "Count"],
        ).properties(height=220),
        width="stretch",
    )

with compare_col:
    st.subheader("CVSS-only vs context-aware ranking")
    if len(table) < 2:
        st.caption("Assess two or more vulnerabilities to compare rankings.")
    else:
        cmp = table[["CVE", "System", "CVSS", "CVSS rank", "Rank"]].rename(
            columns={"Rank": "Our rank"}).copy()
        cmp["Change"] = cmp["CVSS rank"] - cmp["Our rank"]
        cmp["Change"] = cmp["Change"].map(
            lambda d: f"▲ up {d}" if d > 0 else f"▼ down {-d}" if d < 0 else "same")
        st.dataframe(cmp, hide_index=True, width="stretch", height=220)
        moved = int((table["CVSS rank"] != table["Rank"]).sum())
        st.caption(f"{moved} of {len(table)} vulnerabilities rank differently once "
                   "organizational context is considered.")

# ---------------------------------------------------------- full table ---
st.subheader("Prioritized vulnerabilities")
show = st.multiselect("Show risk levels", ui.LEVEL_ORDER, default=ui.LEVEL_ORDER)
view = table[table["Risk level"].isin(show)]


def _color(level):
    fg, bg = ui.LEVEL_COLORS.get(level, ("#444", "#eee"))
    return f"color:{fg};background-color:{bg};font-weight:600"


st.dataframe(
    view.drop(columns=["_i", "CVSS rank"]).style.map(_color, subset=["Risk level"]),
    hide_index=True, width="stretch",
    column_config={
        "Risk score": st.column_config.ProgressColumn(
            "Risk score", min_value=0, max_value=100, format="%.0f"),
        "CVSS": st.column_config.NumberColumn(format="%.1f"),
    },
)

export = table.drop(columns=["_i"]).copy()
export["Recommendation"] = [rows[i][1]["recommendation"] for i in table["_i"]]
st.download_button("Download results (CSV)", export.to_csv(index=False).encode(),
                   file_name="risk_results_all.csv" if show_all else f"risk_results_{run_id}.csv",
                   mime="text/csv",
                   icon=":material/download:")

# ------------------------------------------------------------- details ---
st.subheader("Risk insights")
options = list(table["_i"])
pick = st.selectbox(
    "Vulnerability",
    options,
    format_func=lambda i: f"#{int(table.loc[table['_i'] == i, 'Rank'].iloc[0])} · "
                          f"{rows[i][0]['cve_id']} · {rows[i][1]['risk_level']}",
)
rank = int(table.loc[table["_i"] == pick, "Rank"].iloc[0])
ui.result_card(rows[pick][0], rows[pick][1], rank=rank)

with st.expander("All inputs for this vulnerability"):
    rec = rows[pick][0]
    st.dataframe(
        pd.DataFrame({"Field": list(rec),
                      "Value": [", ".join(v) if isinstance(v, list) else str(v) for v in rec.values()]}),
        hide_index=True, width="stretch",
    )

if show_all:
    st.stop()  # deleting is done per assessment, not from the combined view

st.divider()
if st.button("Delete this assessment", icon=":material/delete:"):
    db.delete_run(user["email"], run_id)
    st.session_state.pop("selected_run", None)
    st.rerun()
