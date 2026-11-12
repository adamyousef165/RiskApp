# Context-Aware AI Vulnerability Risk Assessment – Website

Streamlit website for the PSUT graduation project. A business logs in, enters
organizational context and vulnerability data (form or CSV), and gets a risk
level (Critical / High / Medium / Low), a 0–100 score, a priority rank, the
reasons behind it, and a recommendation.

> The XGBoost model is not connected yet. Until it is, scores come from a
> transparent placeholder formula (likelihood × impact) in `model.py`, and the
> site shows a "Demo scoring" label.

## Run it

In VS Code: **File → Open Folder → RiskApp**, then open the terminal
(**Terminal → New Terminal**):

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

The site opens at http://localhost:8501. Next time, just activate the venv and
run `streamlit run app.py`, or press **F5** in VS Code (needs the Python extension;
select the `.venv` interpreter when asked).

First time: click **Create account**. Accounts and results are saved locally in
`data/riskapp.db` (passwords are hashed). Delete that file to reset everything.

## Files

| File | What it does |
|---|---|
| `app.py` | Starting point: page setup, login gate, sidebar |
| `views/login.py` | Log in / create account |
| `views/assess.py` | Input page: form + CSV upload |
| `views/results.py` | Dashboard: summary, chart, CVSS vs our ranking, ranked table, insights |
| `views/about.py` | About the system |
| `model.py` | Allowed values, validation, scoring, **XGBoost hook** |
| `db.py` | SQLite accounts and saved assessments |
| `ui.py` | Colors, risk badge, result card |
| `sample_vulnerabilities.csv` | 15 demo rows (illustrative values, not official NVD data) |

## For the model team: the contract

The website sends the model **one record per vulnerability** with these fields.
Training data must use the **same column names and the exact same spellings**.

| Field | Type | Allowed values |
|---|---|---|
| `cve_id` | text | `CVE-YYYY-NNNN` (identifier, not a feature) |
| `cvss_score` | number | 0 – 10 |
| `vulnerability_age_days` | integer | 0 – 10000 |
| `affected_users` | integer | 0 – 10,000,000 |
| `connected_systems` | integer | 0 – 100 |
| `business_type` | choice | University, Hospital, Bank, E-commerce, Government, Telecommunication, Other |
| `system_criticality` | choice | Low, Medium, High, Critical |
| `data_sensitivity` | choice | Public, Internal, Confidential, Highly Sensitive |
| `exposure_level` | choice | Internal Only, Employee Access, Registered Users, Public Internet-Facing |
| `business_impact` | choice | Low, Medium, High, Critical |
| `connected_system_criticality` | choice | None, Low, Medium, High, Critical |
| `attack_vector` | choice | Network, Adjacent, Local, Physical |
| `attack_complexity` | choice | Low, High |
| `privileges_required` | choice | None, Low, High |
| `user_interaction` | choice | No, Yes |
| `exploit_available` | choice | No, Yes |
| `known_exploited` | choice | No, Yes |
| `patch_available` | choice | No, Yes |
| `related_assets` | list (`;` in CSV) | Students, Employees, Customers, Financial Records, Medical Records, Grades Database, Authentication System, Payment System, Servers, Databases, APIs, Network Devices, Reputation, Business Operations |
| `system_name`, `system_purpose`, `impact_description` | text | Notes only, **not** model features |

**Output classes:** `Low, Medium, High, Critical` (in that order, i.e. class 0–3).

### Plugging in XGBoost

1. Train the model and save it: `joblib.dump(model, "models/xgb_model.joblib")`
2. In `model.py`, write `encode_features(record)` so it returns the feature
   vector in the same order and encoding used in training.
3. `pip install xgboost joblib scikit-learn`

That's it. `predict()` will use the model automatically, the sidebar will
show "XGBoost model connected", and the rest of the site doesn't change. If
loading fails, the site falls back to demo scoring instead of crashing.
