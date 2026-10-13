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

## Execution

1. Install dependencies:
   `pip install -r requirements.txt`
2. Open or execute the notebook with Jupyter:
   `jupyter notebook SQL_Log_Anomaly_Detection.ipynb`
3. Or run it programmatically with `nbclient` or `jupyter nbconvert --execute`.

## Notes

This is a synthetic-data evaluation because the workspace does not contain a real SQL query log dataset. The model output should therefore be interpreted as a demonstration of the anomaly-detection pipeline on realistic synthetic SQL-access patterns rather than as a real production log-quality assessment.
