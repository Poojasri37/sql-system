# SQL Log Anomaly Detection

This project builds and executes a complete Jupyter notebook for SQL log anomaly detection using an `IsolationForest` model from scikit-learn.

## Overview

The workspace did not contain a usable SQL log dataset, so the notebook inspects the available files, notes the available access-log database, and then generates a clearly labeled synthetic SQL-log dataset designed to include both normal and anomalous database activity patterns.

The pipeline includes:

- Workspace dataset inspection
- Synthetic SQL-log data generation when no real SQL dataset exists
- Exploratory data analysis and class distribution checks
- Data cleaning and preprocessing
- Feature engineering for user activity, SQL query type, timing, frequency, table risk, and data volume
- Reproducible train/test splitting
- Isolation Forest training with fixed random state and contamination
- Risk scoring and explanation generation
- Evaluation metrics and research charts
- Model artifact and prediction export

## Notebook

- `SQL_Log_Anomaly_Detection.ipynb`

## Outputs

- `outputs/charts/` — high-resolution PNG charts
- `outputs/reports/evaluation_report.txt`
- `outputs/reports/metrics.json`
- `outputs/reports/predictions.csv`
- `outputs/models/isolation_forest.joblib`

## Flask application

The Flask application uses the saved model and preprocessing artifact; it does not
retrain the model when serving predictions.

1. Install dependencies:
   `pip install -r requirements.txt`
2. Start the application:
   `python app.py`
3. Open `http://127.0.0.1:5000/login`.
4. Create a workspace account with **Register**, or use one of the
   development-only demonstration accounts listed below.

The demonstration login accounts are `admin` / `admin123` and `analyst` /
`analyst123`. These are development-only credentials. Configure strong unique
`SECRET_KEY` and `JWT_SECRET_KEY` values and replace the demonstration
authentication before deploying this application.

Registered accounts are stored in the local `users.db` SQLite database with
password hashes. The workspace includes separate Overview, Event analysis,
Alerts, Recommendations, and Model insights pages. Event analysis requires
actual event values and does not prefill example records. Feature thresholds
and risk-score calibration are derived from the model's training-data
distribution; changing event values therefore changes the event features and
score. **Load dataset record** fills the form from an actual row in
`synthetic_sql_logs.csv`; the prediction response is shown as JSON. The
Recommendations page provides local, rule-based chat guidance based on the
latest analysis in the current browser tab; it does not call an external AI
service. The local access-log databases are employee/file-access datasets, not
SQL query logs, so they are not used for model training or presented as live
SQL events. Use authorized SQL logs to retrain and validate the model before
operational use.

Evaluation metrics and the alert examples are based on synthetic data; they
are not a live database feed. Recommendations are general guidance.

The API provides `/api/health`, `/api/login`, `/api/metrics`, `/api/predict`,
and `/api/recent-alerts`. Prediction requests use a JWT returned by `/api/login`.

## Execution

1. Open or execute the notebook with Jupyter:
   `jupyter notebook SQL_Log_Anomaly_Detection.ipynb`
2. Or run it programmatically with `nbclient` or `jupyter nbconvert --execute`.

## Notes

This is a synthetic-data evaluation because the workspace does not contain a real SQL query log dataset. The model output should therefore be interpreted as a demonstration of the anomaly-detection pipeline on realistic synthetic SQL-access patterns rather than as a real production log-quality assessment.

The repository includes only the synthetic SQL logs generated for this project.
Other datasets present in the original workspace are unrelated and are not
included.
