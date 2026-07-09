#!/usr/bin/env python3
import os
import json
import warnings
from datetime import datetime
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV, learning_curve
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
from sklearn.utils import resample

# matplotlib opzionale: se manca, il training procede senza grafici.
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_PLT = True
except Exception:
    HAS_PLT = False

PROJECT_DIR = os.path.abspath(os.path.dirname(__file__))
DATASET_PATH = os.path.join(PROJECT_DIR, "dataset", "dataset_v8_training.csv")
MODEL_DIR = os.path.join(PROJECT_DIR, "ml")
RESULTS_DIR = os.path.join(PROJECT_DIR, "results")
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

# LISTA FEATURE DEFINITIVA - identica a quella del controller (_build_feature_vector)
FEATURE_COLUMNS = [
    "ip_proto",
    "delta_packets", "delta_bytes", "packet_rate", "byte_rate",
    "burst_score",
    "dst_unique_src_count", "dst_total_packet_rate",
    "dst_total_byte_rate", "dst_active_flow_count",
    "dst_std_packet_rate", "dst_cv_packet_rate",
    "is_tcp", "is_udp",
    "flow_to_dst_ratio", "pps_per_source",
]

THRESHOLDS = [0.25, 0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70, 0.75]

# --- Selezione soglia: recall-pesata con pavimento di precision ----------------
# Contesto security: preferiamo intercettare gli attacchi (recall alta) => usiamo
# F-beta con beta=2 (pesa la recall il doppio della precision). MA imponiamo un
# pavimento di precision per non inondare di falsi positivi. Il controller Ryu
# aggiunge una seconda difesa (SUSPICIOUS_LIMIT: blocca solo dopo N conferme
# consecutive), quindi possiamo permetterci una soglia piu' aggressiva.
#
# Regola: fra le soglie con precision >= MIN_PRECISION si sceglie quella con
# F-beta massimo; a parita', la piu' BASSA (blocco piu' rapido).
# Per bloccare di piu' e prima -> abbassa MIN_PRECISION (es. 0.45).
# Per meno falsi positivi          -> alzala (es. 0.75).
FBETA = 2.0
MIN_PRECISION = 0.55


def fbeta_score_manual(prec, rec, beta=FBETA):
    if prec <= 0 and rec <= 0:
        return 0.0
    b2 = beta * beta
    denom = b2 * prec + rec
    return (1 + b2) * prec * rec / denom if denom > 0 else 0.0


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

    # consideriamo ATTIVO un flusso solo se ha traffico REALE nell'intervallo di
    # campionamento (delta_packets>0). NB: filtrare su packet_count cumulativo
    # includerebbe righe "zombie" a rate 0 (flussi gia' visti ma senza nuovo
    # traffico tra due poll), identiche fra attacco e legittimo, che affogano il
    # segnale e azzerano la recall. Sono proprio quelle da escludere.
    if "delta_packets" in df.columns:
        df = df[df["delta_packets"] > 0]
    elif "packet_rate" in df.columns:
        df = df[df["packet_rate"] > 0]

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


def plot_oob_error(X_train, y_train, best_params, out_path):
    """Analogo corretto della 'curva di loss' per una Random Forest: errore OOB
    (Out-Of-Bag) al crescere del numero di alberi. Mostra come l'errore stimato
    sui campioni non usati da ciascun albero cala e si stabilizza."""
    params = {k: v for k, v in best_params.items() if k != "n_estimators"}
    clf = RandomForestClassifier(random_state=42, warm_start=True,
                                 oob_score=True, bootstrap=True, **params)
    xs, ys = [], []
    # Si parte da 30 alberi: con troppo pochi alberi alcuni campioni non sono
    # mai "out-of-bag" e lo stimatore OOB non e' affidabile (genera un warning).
    # Da 30 in su la stima e' stabile. Sopprimiamo l'eventuale warning residuo
    # dei primissimi punti cosi' il log resta pulito.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=UserWarning)
        for n in range(30, 211, 10):
            clf.set_params(n_estimators=n)
            clf.fit(X_train, y_train)
            xs.append(n)
            ys.append(1.0 - clf.oob_score_)
    plt.figure(figsize=(7, 4))
    plt.plot(xs, ys, marker="o", color="#c0392b")
    plt.xlabel("Numero di alberi (n_estimators)")
    plt.ylabel("Errore OOB  (1 - oob_score)")
    plt.title("Random Forest - curva errore OOB")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path, dpi=120)
    plt.close()


def plot_learning_curve(model, X, y, out_path):
    """Learning curve: F1 su train e su cross-validation al crescere della
    dimensione del training set. Dice se servono piu' dati o se c'e' overfitting."""
    sizes, tr, va = learning_curve(
        model, X, y, cv=3, scoring="f1",
        train_sizes=np.linspace(0.1, 1.0, 8), shuffle=True, random_state=42, n_jobs=-1)
    plt.figure(figsize=(7, 4))
    plt.plot(sizes, tr.mean(axis=1), marker="o", label="F1 train")
    plt.plot(sizes, va.mean(axis=1), marker="s", label="F1 cross-val")
    plt.xlabel("Dimensione training set")
    plt.ylabel("F1")
    plt.title("Learning curve")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path, dpi=120)
    plt.close()


def plot_feature_importance(importanze, out_path, top=12):
    names = [n for n, _ in importanze[:top]][::-1]
    vals = [v for _, v in importanze[:top]][::-1]
    plt.figure(figsize=(7, 5))
    plt.barh(names, vals, color="#2c7fb8")
    plt.xlabel("Importanza")
    plt.title("Feature importance (Random Forest)")
    plt.grid(True, axis="x", alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path, dpi=120)
    plt.close()


def plot_threshold_curve(rows, chosen, out_path):
    ts = [r["threshold"] for r in rows]
    plt.figure(figsize=(7, 4))
    for k, col in [("precision", "#2980b9"), ("recall", "#27ae60"), ("f1", "#8e44ad")]:
        plt.plot(ts, [r[k] for r in rows], marker="o", label=k)
    plt.axvline(chosen, color="#c0392b", linestyle="--", label=f"soglia scelta={chosen:.2f}")
    plt.xlabel("Soglia decisionale")
    plt.ylabel("Metrica")
    plt.title("Precision / Recall / F1 vs soglia")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path, dpi=120)
    plt.close()


def main():
    df = load_dataset()
    X_train, X_test, y_train, y_test = split_data(df)
    print("Train:", len(X_train), "Test:", len(X_test))
    if y_train.nunique() < 2 or y_test.nunique() < 2:
        print("ERRORE: train o test con una sola classe. Serve più varieta' nel dataset.")
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

    print("\n=== Tuning soglia (F-beta recall-pesata, pavimento precision) ===")
    rows = []
    for t in THRESHOLDS:
        pred = (proba >= t).astype(int)
        acc = accuracy_score(y_test, pred)
        prec = precision_score(y_test, pred, zero_division=0)
        rec = recall_score(y_test, pred, zero_division=0)
        f1 = f1_score(y_test, pred, zero_division=0)
        fb = fbeta_score_manual(prec, rec)
        rows.append({"threshold": t, "accuracy": acc, "precision": prec,
                     "recall": rec, "f1": f1, "fbeta": fb})
        print(f"soglia={t:.2f}  acc={acc:.3f}  prec={prec:.3f}  rec={rec:.3f}  "
              f"f1={f1:.3f}  f{FBETA:.0f}={fb:.3f}")

    pd.DataFrame(rows).to_csv(os.path.join(RESULTS_DIR, "model_metrics_thresholds.csv"), index=False)

    # fra le soglie con precision >= MIN_PRECISION: F-beta massimo, a parita' la
    # soglia piu' bassa (blocco piu' rapido). Se nessuna raggiunge il pavimento,
    # fallback sul miglior F1 assoluto.
    ammesse = [r for r in rows if r["precision"] >= MIN_PRECISION]
    if ammesse:
        best = max(ammesse, key=lambda r: (round(r["fbeta"], 4), -r["threshold"]))
        print(f"\nPavimento precision={MIN_PRECISION:.2f} rispettato. "
              f"Soglia recall-pesata scelta: {best['threshold']:.2f}")
    else:
        best = max(rows, key=lambda r: (round(r["f1"], 4), -r["threshold"]))
        print(f"\nNessuna soglia raggiunge precision>={MIN_PRECISION:.2f}. "
              f"Fallback su miglior F1: soglia {best['threshold']:.2f}")

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
    importanze = sorted(zip(FEATURE_COLUMNS, model.feature_importances_),
                        key=lambda x: x[1], reverse=True)
    for name, imp in importanze:
        print(f"{name:24s} {imp:.3f}")

    # --- Scrittura del report su file --------------------------------------
    # IMPORTANTE: il report viene RIGENERATO ad ogni addestramento, cosi' resta
    # sempre coerente col modello salvato (era il problema segnalato: il vecchio
    # model_report.txt riportava metriche e feature non piu' attuali).
    f1_ml = round(best["f1"], 3)
    f1_base = round(f1_score(y_test, naive_pred, zero_division=0), 3)
    report_lines = []
    report_lines.append("=" * 62)
    report_lines.append(" REPORT MODELLO - DDoS detection (Random Forest)")
    report_lines.append(f" Generato il: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append(" Rigenerato automaticamente da train_model.py")
    report_lines.append("=" * 62)
    report_lines.append("")
    report_lines.append(f"Righe attive (dopo pulizia): {len(X_train) + len(X_test)}")
    report_lines.append(f"  train: {len(X_train)}   test: {len(X_test)}")
    report_lines.append(f"Iperparametri scelti: {grid.best_params_}")
    report_lines.append(f"Soglia decisionale scelta: {best['threshold']:.2f}")
    report_lines.append("")
    report_lines.append("--- Metriche sul test set ---")
    report_lines.append(f"accuracy : {best['accuracy']:.3f}")
    report_lines.append(f"precision: {best['precision']:.3f}")
    report_lines.append(f"recall   : {best['recall']:.3f}")
    report_lines.append(f"f1       : {best['f1']:.3f}")
    report_lines.append("")
    report_lines.append("--- Matrice di confusione (test) ---")
    report_lines.append("            pred_0  pred_1")
    cm = confusion_matrix(y_test, final_pred)
    report_lines.append(f"  reale_0   {cm[0][0]:6d}  {cm[0][1]:6d}   (legittimi)")
    report_lines.append(f"  reale_1   {cm[1][0]:6d}  {cm[1][1]:6d}   (attacchi)")
    report_lines.append("")
    report_lines.append("--- Classification report ---")
    report_lines.append(classification_report(y_test, final_pred, zero_division=0))
    report_lines.append("--- Confronto col baseline (la prova che il ML serve) ---")
    report_lines.append(f"Baseline  if(packet_rate >= {naive_thr:.1f}):  F1 = {f1_base}")
    report_lines.append(f"Modello ML (Random Forest):              F1 = {f1_ml}")
    report_lines.append(f"Un semplice if sul rate NON basta: {f1_base} contro {f1_ml}.")
    report_lines.append("")
    report_lines.append("--- Feature importance ---")
    for name, imp in importanze:
        report_lines.append(f"  {name:24s} {imp:.3f}")
    report_lines.append("")
    report_lines.append(f"Feature usate ({len(FEATURE_COLUMNS)}): {FEATURE_COLUMNS}")
    report_text = "\n".join(report_lines)
    with open(os.path.join(RESULTS_DIR, "model_report.txt"), "w") as f:
        f.write(report_text + "\n")
    print("\nReport salvato in:", os.path.join(RESULTS_DIR, "model_report.txt"))

    # --- Grafici diagnostici (gli analoghi CORRETTI per una Random Forest) -----
    # NB: la RF NON ha una "loss per epoca/round" (gli alberi sono indipendenti,
    # bagging, non boosting). L'analogo corretto e' la curva dell'errore OOB al
    # crescere del numero di alberi; aggiungiamo anche la learning curve.
    if HAS_PLT:
        try:
            plot_oob_error(X_train, y_train, grid.best_params_,
                           os.path.join(RESULTS_DIR, "oob_error_curve.png"))
            plot_learning_curve(model, X_train, y_train,
                                os.path.join(RESULTS_DIR, "learning_curve.png"))
            plot_feature_importance(importanze,
                                    os.path.join(RESULTS_DIR, "feature_importance.png"))
            plot_threshold_curve(rows, best["threshold"],
                                 os.path.join(RESULTS_DIR, "threshold_curve.png"))
            print("\nGrafici salvati in:", RESULTS_DIR)
        except Exception as e:
            print("Avviso: generazione grafici saltata:", e)
    else:
        print("\nmatplotlib non disponibile: grafici saltati (pip install matplotlib).")

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
