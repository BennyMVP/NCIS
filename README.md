# SDN DDoS Detection and Mitigation

Rilevamento e mitigazione automatica di attacchi DoS/DDoS in ambiente SDN
(Software Defined Networking) emulato, mediante Mininet, controller Ryu,
OpenFlow 1.3 e un modello di Machine Learning (Random Forest).

---

## 1. Descrizione

Il progetto realizza una rete SDN emulata in Mininet in cui un controller Ryu
monitora le statistiche dei flussi OpenFlow, classifica il traffico diretto a un
server protetto (h4, 10.0.0.4) tramite un modello Random Forest e installa
automaticamente regole DROP selettive verso le sole sorgenti riconosciute come
sospette.

A differenza di un approccio a soglia fissa, la decisione di blocco è affidata al
modello, addestrato su feature di flusso (rate istantanei, dimensione media dei
pacchetti) e su feature aggregate verso la destinazione (numero di sorgenti, rate
totale, flussi attivi). Il blocco non interessa l'intera porta dello switch ma la
singola coppia `sorgente -> vittima`, evitando l'over-blocking del traffico
legittimo.

---

## 2. Struttura del progetto

```
DDOS/
├── topology/
│   ├── network_core_access.py     # topologia Mininet core/access (demo)
│   └── auto_collect.py            # topologia automatica per la raccolta dataset
├── controller/
│   ├── ml_detector_controller_final.py  # controller finale: detection + mitigazione
│   └── dataset_collector_auto.py        # collector per la raccolta automatica del dataset
├── scripts/
│   ├── udp_realistic_sender.py    # generatore UDP con rate/payload/burst variabili
│   ├── traffic_udp_realistic_v8.mn      # scenario demo (legittimo + attacco)
│   ├── traffic_v8_label0_normal.mn      # scenario raccolta manuale (normale)
│   ├── traffic_v8_label1_attack.mn      # scenario raccolta manuale (attacco distribuito)
│   └── traffic_v8_label1_attack_single.mn  # scenario raccolta manuale (attacco singolo)
├── dataset/
│   └── dataset_v8_training.csv     # dataset raccolto dalla rete emulata
├── ml/
│   ├── best_model.joblib          # modello Random Forest serializzato
│   └── model_metadata.json        # feature, soglia e metriche del modello
├── results/                       # log della demo e dump delle regole OpenFlow
├── train_model.py                 # addestramento del modello
└── run_collect.sh                 # raccolta automatica del dataset + training
```

---

## 3. Prerequisiti

Ambiente di riferimento: Ubuntu 22.04.

Componenti software: Open vSwitch, Mininet, controller Ryu, Python 3 con
scikit-learn, pandas, numpy, joblib.

```bash
sudo apt update
sudo apt install -y git vim python3-pip openvswitch-switch mininet iperf3
pip3 install --break-system-packages scikit-learn pandas numpy joblib
```

### Avvio di Ryu in locale

In questo progetto il controller Ryu viene eseguito da una copia locale presente
nella cartella `ryu/`, anziché dall'installazione di sistema. Il comando base è:

```bash
PYTHONPATH=./ryu python3 ryu/bin/ryu-manager <file_controller>
```

Tutti i comandi che seguono usano questa forma. Eseguire sempre dalla cartella
radice del progetto.

---

## 4. Guida all'esecuzione

### 4.1 Raccolta del dataset e addestramento (un solo comando)

Lo script `run_collect.sh` esegue l'intera pipeline: avvia il collector, lancia la
topologia automatica che genera le fasi di traffico (normale, attacco distribuito,
attacco singolo) ripetute su più round, e infine addestra il modello.

```bash
chmod +x run_collect.sh
./run_collect.sh
```

Parametri opzionali (numero di round e durata di ogni fase):

```bash
ROUNDS=3 PHASE_SECONDS=60 ./run_collect.sh
```

Al termine, il dataset si trova in `dataset/dataset_v8_training.csv` e il modello
aggiornato in `ml/best_model.joblib`. Per riaddestrare senza rifare la raccolta:

```bash
python3 train_model.py
```

### 4.2 Demo: rilevamento e mitigazione in tempo reale

La demo richiede due terminali. Prima di avviarla, copiare il generatore di
traffico nella posizione attesa dagli scenari:

```bash
cp scripts/udp_realistic_sender.py /tmp/
```

**Terminale 1 — controller Ryu:**

```bash
PYTHONPATH=./ryu python3 ryu/bin/ryu-manager controller/ml_detector_controller_final.py
```

**Terminale 2 — rete Mininet:**

```bash
sudo python3 topology/network_core_access.py
```

**Dentro la CLI di Mininet**, avviare lo scenario di traffico:

```bash
source scripts/traffic_udp_realistic_v8.mn
```

### 4.3 Verifica della mitigazione

Dopo alcune decine di secondi, sempre dalla CLI di Mininet, ispezionare le tabelle
di flusso degli switch:

```bash
sh ovs-ofctl -O OpenFlow13 dump-flows s0
sh ovs-ofctl -O OpenFlow13 dump-flows s1
sh ovs-ofctl -O OpenFlow13 dump-flows s2
sh ovs-ofctl -O OpenFlow13 dump-flows s3
sh ovs-ofctl -O OpenFlow13 dump-flows s4
```

La presenza di regole con `priority=200`, match `ip,nw_src=<sorgente>,nw_dst=10.0.0.4`
e `actions=drop` conferma che la mitigazione è stata applicata effettivamente sugli
switch, in modo selettivo per sorgente.

---

## 5. Parametri principali del controller

| Parametro | Valore | Ruolo |
|---|---|---|
| `PROTECTED_SERVER_IP` | 10.0.0.4 | Server protetto (vittima h4) |
| `SUSPICIOUS_LIMIT` | 4 | Rilevazioni consecutive prima del blocco |
| `BLOCK_TIMEOUT` | 300 s | Durata della regola DROP |
| soglia ML | 0.35 | Soglia di probabilità per la classificazione |

Le condizioni aggregate verso il server protetto (numero di sorgenti, rate totale,
flussi attivi) sono calcolate e registrate nei log a fini di analisi, ma non
intervengono nella decisione di blocco, che è affidata al modello.
