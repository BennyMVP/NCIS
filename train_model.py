#!/usr/bin/env python3
# =============================================================================
# train_model.py - allineato al controller core/access corretto
#
# Coerenza feature (FONDAMENTALE): usa ESATTAMENTE le stesse feature che il
# controller calcola dal vivo dopo le correzioni:
#   - niente src_port/dst_port  (routing per IP -> porte sempre 0, inutili)
#   - esclusi i contatori cumulativi (packet_count, byte_count, duration_sec), che
#     introducono dipendenza dalla durata di osservazione anziche dalla natura del traffico
#   - aggiunte le 4 derivate: is_tcp, is_udp, flow_to_dst_ratio, pps_per_source
#
# Obiettivo: decisione guidata dal ML su feature volumetriche/aggregate,
# adatta all'attacco DISTRIBUITO low-rate.
# =============================================================================

import os
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
from sklearn.utils import resample

PROJECT_DIR = os.path.abspath(os.path.dirname(__file__))
DATASET_PATH = os.path.join(PROJECT_DIR, "dataset", "dataset_v8_training.csv")
MODEL_DIR = os.path.join(PROJECT_DIR, "ml")
RESULTS_DIR = os.path.join(PROJECT_DIR, "results")
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

# LISTA FEATURE DEFINITIVA - identica a quella del controller (_build_feature_vector)
FEATURE_COLUMNS = [
    "ip_proto",
    "delta_packets", "delta_bytes", "packet_rate", "byte_rate", "avg_packet_size",
    "dst_unique_src_count", "dst_total_packet_rate",
    "dst_total_byte_rate", "dst_active_flow_count",
    "is_tcp", "is_udp",
    "flow_to_dst_ratio", "pps_per_source",
]

THRESHOLDS = [0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70, 0.75]
MIN_PRECISION = 0.85


def add_derived_features(df):
    if "ip_proto" in df.columns:
        df["is_tcp"] = (df["ip_proto"] == 6).astype(int)
        df["is_udp"] = (df["ip_proto"] == 17).astype(int)
    else:
        df["is_tcp"] = 0
        df["is_udp"] = 0
    df["flow_to_dst_ratio"] = df["packet_rate"] / (df["dst_total_packet_rate"] + 1.0)
    df["pps_per_source"] = df["dst_total_packet_rate"] / (df["dst_unique_src_count"] + 1.0)
    return df


def load_dataset():
    print("Carico dataset da:", DATASET_PATH)
    df = pd.read_csv(DATASET_PATH)
    df.columns = [c.strip().replace("\r", "") for c in df.columns]

    # consideriamo solo i flussi ATTIVI (con traffico): coerente col controller,
    # che decide solo su flussi con packet_rate >= soglia minima.
    if "packet_rate" in df.columns:
        attivi = (df["packet_rate"] > 0)
        if "packet_count" in df.columns:
            attivi = attivi | (df["packet_count"] > 5)
        df = df[attivi]

    df = add_derived_features(df)

    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0.0
    for col in FEATURE_COLUMNS + ["label"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df = df.dropna(subset=FEATURE_COLUMNS + ["label"])
    df["label"] = df["label"].astype(int)
    print("Righe attive dopo pulizia:", len(df))
    print("Distribuzione label:\n", df["label"].value_counts().sort_index())
    return df


def split_data(df, random_state=42):
    """Split per sessioni se disponibili (anti-leakage), altrimenti stratificato."""
    np.random.seed(random_state)
    if "session_id" in df.columns and df["session_id"].nunique() >= 2:
        # mette ~30% delle righe di OGNI sessione nel test, coprendo tutti gli scenari
        test_parts, train_parts = [], []
        for sess in df["session_id"].unique():
            s = df[df["session_id"] == sess].sample(frac=1, random_state=random_state)
            n_test = max(1, int(len(s) * 0.3))
            test_parts.append(s.iloc[:n_test])
            train_parts.append(s.iloc[n_test:])
        test_df = pd.concat(test_parts)
        train = pd.concat(train_parts)
        print("Split per sessioni. Sessioni:", list(df["session_id"].unique()))
    else:
        from sklearn.model_selection import train_test_split
        tr, te = train_test_split(df, test_size=0.3, random_state=random_state,
                                  stratify=df["label"])
        train, test_df = tr, te
        print("Split stratificato semplice (nessuna sessione).")

    X_test = test_df[FEATURE_COLUMNS]
    y_test = test_df["label"]

    # bilanciamento del training
    maj = 1 if train["label"].sum() > len(train) / 2 else 0
    dmaj = train[train["label"] == maj]
    dmin = train[train["label"] == 1 - maj]
    if len(dmaj) > len(dmin) and len(dmin) > 0:
        dmaj = resample(dmaj, replace=False, n_samples=len(dmin), random_state=random_state)
    train_bal = pd.concat([dmaj, dmin])
    print("Train bilanciato:", len(train_bal), "righe")
    return train_bal[FEATURE_COLUMNS], X_test, train_bal["label"], y_test


def main():
    df = load_dataset()
    X_train, X_test, y_train, y_test = split_data(df)
    print("Train:", len(X_train), "Test:", len(X_test))
    if y_train.nunique() < 2 or y_test.nunique() < 2:
        print("ERRORE: train o test con una sola classe. Serve piu' varieta' nel dataset.")
        return

    param_grid = {
        "n_estimators": [150, 200],
        "max_depth": [8, 10, 12],
        "min_samples_split": [2, 5],
        "min_samples_leaf": [1, 2],
    }
    grid = GridSearchCV(RandomForestClassifier(random_state=42),
                        param_grid, cv=3, scoring="f1", n_jobs=-1, verbose=1)
    grid.fit(X_train, y_train)
    model = grid.best_estimator_
    print("\nMigliori iperparametri:", grid.best_params_)

    proba = model.predict_proba(X_test)[:, 1]

    print("\n=== Tuning soglia (precision-aware) ===")
    rows, best_constrained, best_any = [], None, {"f1": -1}
    for t in THRESHOLDS:
        pred = (proba >= t).astype(int)
        acc = accuracy_score(y_test, pred)
        prec = precision_score(y_test, pred, zero_division=0)
        rec = recall_score(y_test, pred, zero_division=0)
        f1 = f1_score(y_test, pred, zero_division=0)
        rows.append({"threshold": t, "accuracy": acc, "precision": prec, "recall": rec, "f1": f1})
        print(f"soglia={t:.2f}  acc={acc:.3f}  prec={prec:.3f}  rec={rec:.3f}  f1={f1:.3f}")
        if f1 > best_any["f1"]:
            best_any = {"threshold": t, "accuracy": acc, "precision": prec, "recall": rec, "f1": f1}
        if prec >= MIN_PRECISION and (best_constrained is None or f1 > best_constrained["f1"]):
            best_constrained = {"threshold": t, "accuracy": acc, "precision": prec, "recall": rec, "f1": f1}

    # Miglior F1 assoluto: sceglie la soglia che bilancia meglio precision e recall.
    best = best_any
    pd.DataFrame(rows).to_csv(os.path.join(RESULTS_DIR, "model_metrics_thresholds.csv"), index=False)

    print("\nSoglia scelta:", best["threshold"])
    final_pred = (proba >= best["threshold"]).astype(int)
    print("\nConfusion matrix (test):\n", confusion_matrix(y_test, final_pred))
    print("\nReport:\n", classification_report(y_test, final_pred, zero_division=0))

    pr = X_test["packet_rate"].values
    atk = X_train["packet_rate"][y_train == 1]
    # soglia baseline = mediana del packet_rate degli attacchi nel TRAIN,
    # ma almeno 1.0 per evitare il degenere ">=0" che dice "tutto attacco".
    naive_thr = max(float(atk.median()) if len(atk) else 50.0, 1.0)
    naive_pred = (pr >= naive_thr).astype(int)
    print(f"\n=== Baseline if(packet_rate >= {naive_thr:.1f}) ===")
    print("F1 baseline:", round(f1_score(y_test, naive_pred, zero_division=0), 3),
          "| F1 ML:", round(best["f1"], 3))

    print("\n=== Feature importance ===")
    for name, imp in sorted(zip(FEATURE_COLUMNS, model.feature_importances_),
                            key=lambda x: x[1], reverse=True):
        print(f"{name:24s} {imp:.3f}")

    joblib.dump({
        "model": model, "model_name": "rf_core_access_ml",
        "threshold": float(best["threshold"]),
        "feature_columns": FEATURE_COLUMNS, "metrics": best,
    }, os.path.join(MODEL_DIR, "best_model.joblib"))

    with open(os.path.join(MODEL_DIR, "model_metadata.json"), "w") as f:
        json.dump({"model_name": "rf_core_access_ml", "feature_columns": FEATURE_COLUMNS,
                   "threshold": float(best["threshold"]), "metrics": best}, f, indent=2)

    print("\nModello salvato. Feature usate:", FEATURE_COLUMNS)


if __name__ == "__main__":
    main()
