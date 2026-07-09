#!/bin/bash
# =============================================================================
# run_collect.sh - UN SOLO COMANDO per raccogliere il dataset e addestrare.
#
# Fa tutto da solo:
#   1. pulisce l'ambiente Mininet
#   2. copia il sender E il sink UDP in /tmp
#   3. avvia il collector (in background) che legge l'etichetta dinamica
#   4. lancia la topologia automatica che esegue tutte le fasi x N round
#   5. ferma il collector
#   6. addestra il modello
#
# USO:
#   chmod +x run_collect.sh         (una volta sola)
#   ./run_collect.sh                (3 round, fasi da 60s - default)
#   ROUNDS=2 PHASE_SECONDS=45 ./run_collect.sh   (personalizzato)
#
# NOTA: serve sudo per Mininet. Lo script lo chiede dove necessario.
# =============================================================================

set -e
cd "$(dirname "$0")"   # vai nella cartella del progetto

export ROUNDS="${ROUNDS:-3}"
export PHASE_SECONDS="${PHASE_SECONDS:-60}"

echo "============================================="
echo " RACCOLTA AUTOMATICA DATASET"
echo " Round: $ROUNDS  |  Durata fase: ${PHASE_SECONDS}s"
echo " Tempo stimato: ~$(( ROUNDS * 3 * (PHASE_SECONDS + 8) / 60 )) minuti"
echo "============================================="

# 1. pulizia
echo "[1/6] Pulizia ambiente Mininet..."
sudo mn -c > /dev/null 2>&1 || true
rm -f /tmp/current_label.txt
rm -f dataset/dataset_v8_training.csv ml/best_model.joblib

# 2. sender + sink in /tmp
echo "[2/6] Copio sender e sink UDP in /tmp..."
cp scripts/udp_realistic_sender.py /tmp/
cp scripts/udp_sink.py /tmp/

# 3. avvia collector in background
echo "[3/6] Avvio collector (background)..."
if [ -x ./ryu/bin/ryu-manager ]; then
    RYU_CMD="python3 ryu/bin/ryu-manager"
    export PYTHONPATH=./ryu
else
    RYU_CMD="ryu-manager"
fi

$RYU_CMD controller/dataset_collector_auto.py \
    > /tmp/collector_auto.log 2>&1 &
RYU_PID=$!
sleep 5   # tempo perché Ryu si avvii e ascolti su 6653

# 4. topologia automatica (esegue tutte le fasi)
echo "[4/6] Avvio raccolta automatica (questo richiede qualche minuto)..."
sudo -E python3 topology/auto_collect.py

# 5. ferma il collector
echo "[5/6] Fermo il collector..."
kill $RYU_PID 2>/dev/null || true
sleep 2
sudo mn -c > /dev/null 2>&1 || true

# riepilogo righe raccolte
if [ -f dataset/dataset_v8_training.csv ]; then
    RIGHE=$(wc -l < dataset/dataset_v8_training.csv)
    echo "    Dataset raccolto: $RIGHE righe in dataset/dataset_v8_training.csv"
else
    echo "    ATTENZIONE: nessun dataset prodotto. Controlla /tmp/collector_auto.log"
    exit 1
fi

# 6. addestramento
echo "[6/6] Addestro il modello..."
python3 train_model.py

echo "============================================="
echo " FATTO. Modello in ml/best_model.joblib"
echo " Log collector: /tmp/collector_auto.log"
echo "============================================="
