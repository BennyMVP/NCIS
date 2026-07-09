# SDN DDoS Detection and Mitigation

Rilevamento e mitigazione automatica di attacchi DoS/DDoS su UDP in una rete SDN
emulata con Mininet, controller Ryu, OpenFlow 1.3 e un modello Random Forest.

Un controller Ryu monitora i flussi OpenFlow diretti al server protetto `h4`
(`10.0.0.4`), estrae per ogni flusso un insieme di feature di rate e di contesto
aggregato, li classifica con un Random Forest e, quando riconosce un attacco,
installa regole OpenFlow `DROP` selettive sulla sola coppia `sorgente -> vittima`.
Il blocco non spegne l'intera porta dello switch: colpisce unicamente la
comunicazione tra l'attaccante e `h4`, così il resto della rete continua a
funzionare.

---

## Che cosa fa il progetto

Il sistema affronta l'intero ciclo di difesa da un attacco DDoS in ambito SDN:

1. **Generazione del traffico.** Host legittimi e host attaccanti generano
   traffico UDP verso la vittima con profili di comportamento diversi (rate,
   dimensione dei pacchetti, burst e regolarità del timing).
2. **Raccolta del dataset.** Il controller-collector osserva i flussi, calcola
   le feature ed etichetta ogni riga come traffico normale (0) o attacco (1),
   producendo il dataset di addestramento.
3. **Addestramento del modello.** Un Random Forest viene addestrato sul dataset,
   con selezione della soglia decisionale e confronto con una baseline a soglia.
4. **Rilevamento e mitigazione live.** Il controller di detection carica il
   modello, valuta i flussi in tempo reale e blocca le sorgenti d'attacco
   installando regole DROP temporanee, senza toccare il traffico legittimo.

Il problema è modellato come **classificazione binaria** (traffico normale
contro traffico d'attacco): la risposta del sistema — installare una regola di
blocco — è la stessa indipendentemente dal tipo di attacco, quindi distinguere
attacco singolo da distribuito non aggiungerebbe valore all'azione difensiva.
Il perimetro del lavoro è il **traffico flood UDP**, singolo e distribuito.

---

## Struttura del progetto

```text
DDOS_progetto/
├── README.md
├── PROGETTO_NCI_Beneduce_Buonanno.pdf
├── run_collect.sh                      # un comando: raccoglie il dataset e addestra
├── train_model.py                      # addestramento del Random Forest
├── topology/
│   ├── network_core_access.py          # topologia (demo/test manuale)
│   └── auto_collect.py                 # topologia + tutte le fasi di raccolta (automatico)
├── controller/
│   ├── dataset_collector_auto.py       # osserva i flussi, calcola le feature, etichetta
│   └── ml_detector_controller_final.py # detection + mitigazione (regole DROP)
├── scripts/
│   ├── udp_realistic_sender.py         # generatore di traffico UDP parametrico
│   ├── udp_sink.py                     # listener UDP su h4 (evita ICMP port-unreachable)
│   └── test_in_mininet/
│       ├── verify_1_legittimo.mn       # test: solo traffico legittimo
│       ├── verify_2_singolo.mn         # test: attacco singolo volumetrico
│       ├── verify_3_distribuito.mn     # test: attacco distribuito coordinato
│       └── verify_full.mn              # test: le tre fasi in sequenza
├── dataset/
│   └── dataset_v8_training.csv         # dataset generato (rigenerabile)
├── ml/
│   ├── best_model.joblib               # modello addestrato
│   └── model_metadata.json             # feature, soglia, metriche
├── figures/
│   ├── topologia_core_access.drawio
│   └── pipeline_detection_mitigazione.drawio
└── results/
    ├── model_report.txt                # report rigenerato ad ogni addestramento
    ├── model_metrics_thresholds.csv
    ├── feature_importance.png
    ├── threshold_curve.png
    ├── learning_curve.png
    └── oob_error_curve.png
```

---

## Prerequisiti

```bash
sudo apt update
sudo apt install -y python3-pip openvswitch-switch mininet iperf3
pip3 install --break-system-packages pandas numpy scikit-learn joblib matplotlib ryu
```

Se nella VM è presente una copia locale di Ryu nella cartella `./ryu`, il
controller si avvia così:

```bash
PYTHONPATH=./ryu python3 ryu/bin/ryu-manager controller/ml_detector_controller_final.py
```

---

## Come si allestisce il dataset e si addestra il modello

Il dataset viene **raccolto durante una fase iniziale eseguita da noi**: gli host
generano traffico UDP verso `h4`, il collector osserva i flussi e li etichetta,
e il risultato è il CSV di addestramento. Tutto questo è automatizzato in un solo
comando.

```bash
cd ~/Scrivania/DDOS_progetto
chmod +x run_collect.sh
sudo -E ./run_collect.sh
```

`run_collect.sh` esegue in sequenza: pulizia di Mininet, copia di sender e sink
in `/tmp`, avvio del collector, esecuzione di tutte le fasi di traffico (normale,
attacco distribuito, attacco singolo) per il numero di round previsto, arresto
del collector e addestramento del modello. Al termine si ottengono:

```text
dataset/dataset_v8_training.csv   dataset generato
ml/best_model.joblib              modello addestrato
ml/model_metadata.json            feature, soglia, metriche
results/model_report.txt          metriche, matrice di confusione, baseline
```

Per una raccolta più breve (prova rapida):

```bash
ROUNDS=2 PHASE_SECONDS=45 sudo -E ./run_collect.sh
```

Per riaddestrare soltanto sul dataset già raccolto, senza rifare la raccolta:

```bash
python3 train_model.py
```

---

## Gli script

- **`udp_realistic_sender.py`** genera il traffico UDP. È lo stesso programma per
  tutti gli host: cambiano solo i parametri, ed è questo che distingue un
  legittimo da un attaccante. Il profilo **legittimo** ha timing irregolare
  (jitter alto), payload di dimensione molto variabile e burst rari, come un
  utente reale. Il profilo **attaccante** ha timing regolare da macchina (jitter
  bassissimo), payload più uniformi e, nel caso distribuito, più sorgenti
  coordinate sulla stessa vittima.
- **`udp_sink.py`** gira su `h4` e tiene aperte le porte UDP ricevute, scartando
  i pacchetti. Serve perché senza un ricevente in ascolto i pacchetti UDP
  colpirebbero porte chiuse e il kernel di `h4` risponderebbe con messaggi ICMP
  "port unreachable", che inquinerebbero il dataset. Con il sink il traffico
  resta UDP pulito.
- **`dataset_collector_auto.py`** è il controller usato in fase di raccolta:
  interroga le statistiche dei flussi, calcola le feature ed etichetta le righe.
- **`ml_detector_controller_final.py`** è il controller di produzione: carica il
  modello, valuta i flussi live e installa le regole DROP.
- **`auto_collect.py`** definisce la topologia e orchestra automaticamente le
  fasi di traffico per la raccolta.
- **`network_core_access.py`** è la topologia usata per la demo e i test manuali.
- Gli script `.mn` in `scripts/test_in_mininet/` sono i test di mitigazione da
  lanciare dentro la CLI di Mininet.

---

## Comandi utili per i test di mitigazione

I test si eseguono con due terminali (controller e topologia) più, opzionalmente,
un terzo terminale per i controlli al volo. Il sender e il sink vanno copiati in
`/tmp` una volta prima di ogni test.

**Preparazione (shell normale):**

```bash
sudo rm -f /tmp/h4_sink.log /tmp/snd_*.log /tmp/controller_log.txt
sudo mn -c
cp scripts/udp_realistic_sender.py scripts/udp_sink.py /tmp/
```

**Terminale 1 - controller (con salvataggio del log):**

```bash
cd ~/Scrivania/DDOS_progetto
PYTHONPATH=./ryu python3 ryu/bin/ryu-manager controller/ml_detector_controller_final.py 2>&1 | tee /tmp/controller_log.txt
```

**Terminale 2 - topologia:**

```bash
cd ~/Scrivania/DDOS_progetto
sudo -E python3 topology/network_core_access.py
```

**Dentro `mininet>` - scegliere un test:**

```bash
source scripts/test_in_mininet/verify_1_legittimo.mn     # solo traffico legittimo
source scripts/test_in_mininet/verify_2_singolo.mn       # attacco singolo volumetrico
source scripts/test_in_mininet/verify_3_distribuito.mn   # attacco distribuito
source scripts/test_in_mininet/verify_full.mn            # le tre fasi in sequenza
```

**Verifica del sink (terzo terminale):**

```bash
cat /tmp/h4_sink.log        # deve mostrare: [udp_sink] in ascolto su ... porte UDP
```

**Estrazione dei risultati dal log del controller (shell normale, dopo `exit`):**

```bash
grep "BLOCCO" /tmp/controller_log.txt
grep "sospetto" /tmp/controller_log.txt | grep -oE "10.0.0.[0-9]+ -> 10.0.0.4: conteggio [0-9]/4" | sort | uniq -c
```

Tra un test e l'altro conviene ripulire (`exit` da Mininet, poi `sudo mn -c`),
perché le regole DROP durano 300 secondi e resterebbero attive nel test
successivo.

---

## Parametri del controller

| Parametro | Valore | Ruolo |
| --- | --- | --- |
| `PROTECTED_SERVER_IP` | `10.0.0.4` | Server protetto (h4) |
| `THRESHOLD_OVERRIDE` | `0.40` | Soglia probabilistica del Random Forest |
| `MIN_FLOW_PPS_FOR_ML` | `1.0` | Evita predizioni su flussi dormienti |
| `AGG_MIN_SOURCES` | `4` | Sorgenti minime per considerare la vittima sotto attacco |
| `AGG_MIN_PACKET_RATE` | `100.0` | Rate aggregato minimo verso la vittima |
| `AGG_MIN_ACTIVE_FLOWS` | `4` | Flussi attivi minimi verso la vittima |
| `SUSPICIOUS_LIMIT` | `4` | Conferme consecutive prima del blocco |
| `BLOCK_TIMEOUT` | `300 s` | Durata della regola DROP |

Un flusso viene bloccato solo se sono verificate tutte queste condizioni:

```text
BLOCCO = predizione ML positiva
         AND contesto aggregato d'attacco verso 10.0.0.4
         AND 4 conferme consecutive
```

Le soglie del contesto aggregato (`AGG_*`) definiscono quando il server è
considerato sotto attacco. Sono tenute sopra il normale carico legittimo (alcuni
utenti che sommano poche decine di pps) e sotto il volume/numero di sorgenti di
un vero attacco. È questo doppio filtro — modello sul singolo flusso più contesto
aggregato più contatore di conferme — a proteggere il traffico legittimo dai
blocchi errati.

---

## Dataset

Tutto il traffico è UDP. Il dataset generato contiene:

```text
Totale righe CSV: 4703   (tutte UDP, proto=17; nessun ICMP)
label 0 normale: 3052
label 1 attacco: 1651
```

In addestramento si usano le righe attive (`delta_packets > 0`):

```text
Righe attive: 3942
label 0 normale: 2413
label 1 attacco: 1529
```

Le sessioni corrispondono alle tre fasi: traffico normale, attacco distribuito,
attacco singolo. Gli attaccanti del caso distribuito sono `h3`, `h5`, `h9`,
`h12`; gli host legittimi di controllo sono `h1`, `h2`, `h8`.

Nota sui protocolli: nell'impostazione iniziale il traffico legittimo includeva
connessioni TCP (`iperf3`, in ascolto sulla porta di servizio) e ICMP (`ping`).
Il numero di porta del server che compariva nel primo schema della topologia si
riferiva a quel servizio TCP sulla vittima. Nella versione attuale il traffico è
interamente UDP e la vittima esegue soltanto il sink UDP, quindi quel riferimento
non è più presente: non c'è più un servizio TCP né traffico ICMP nel dataset.

I diagrammi della topologia e della pipeline sono forniti in formato editabile
in `figures/` (`topologia_core_access.drawio`, `pipeline_detection_mitigazione.drawio`)
e vanno esportati in PNG/PDF per l'inclusione nel documento.

---

## Feature del modello

Il modello usa 16 feature, coerenti tra `train_model.py`, `ml/model_metadata.json`,
`ml/best_model.joblib`, il controller e `results/model_report.txt`. Sono escluse
le porte L4 e i contatori cumulativi perché poco generalizzabili.

```text
ip_proto              dst_unique_src_count   is_tcp
delta_packets         dst_total_packet_rate  is_udp
delta_bytes           dst_total_byte_rate    flow_to_dst_ratio
packet_rate           dst_active_flow_count  pps_per_source
byte_rate             dst_std_packet_rate
burst_score           dst_cv_packet_rate
```

---

## Risultati dell'addestramento

```text
soglia:     0.40
accuracy:   0.972
precision:  0.938
recall:     0.988
f1:         0.963
```

Matrice di confusione sul test set:

```text
              Predetto normale   Predetto attacco
Reale normale        717                28
Reale attacco          5               426
```

Confronto con la baseline a soglia, che dimostra la necessità del modello:

```text
Baseline  if(packet_rate >= 23.5):  F1 = 0.32
Modello Random Forest:              F1 = 0.963
```

Poiché il traffico legittimo e quello d'attacco hanno un rate volutamente
sovrapposto, una semplice soglia sul packet-rate fallisce (F1 0.32): il modello
deve combinare più feature (volume, regolarità del flusso, contesto aggregato)
per separare le due classi.

### Perché le metriche non sono a 1.0

In una versione precedente il report riportava metriche pari a 1.0 (accuracy,
precision, recall, f1 tutti perfetti). Un risultato del genere non è un pregio:
segnala che il problema era troppo facile e/o che c'era una scorciatoia nei dati.
Erano presenti due scorciatoie: (1) l'attacco aveva un rate nettamente più alto
del traffico legittimo, quindi bastava una soglia sul packet-rate per separarli;
(2) il traffico legittimo conteneva molte righe ICMP (messaggi di errore generati
da porte chiuse), mentre l'attacco era solo UDP, così il modello poteva separare
le classi guardando il solo protocollo. Con un problema così banale, qualsiasi
classificatore raggiunge il 100%.

Nella versione attuale entrambe le scorciatoie sono state eliminate: il rate
degli attaccanti è stato sovrapposto a quello dei legittimi e tutto il traffico è
UDP (il sink su h4 evita l'ICMP spurio). Di conseguenza il problema è diventato
realistico e le metriche sono scese a valori credibili (accuracy 0.972, non 1.0).
La prova che il problema ora è non banale è la baseline a soglia, che crolla a
F1 0.32: se bastasse un `if`, la baseline sarebbe alta quanto il modello. Le
feature di protocollo (`ip_proto`, `is_tcp`, `is_udp`) hanno infatti importanza
nulla, proprio perché non esiste più la scorciatoia dell'ICMP.

---

## Risultati dei test di mitigazione

I test sono stati eseguiti nei tre scenari, con traffico legittimo di sottofondo
sempre presente.

| Scenario | Esito atteso | Esito ottenuto |
| --- | --- | --- |
| Solo legittimo | nessun blocco | nessun blocco, legittimi 0% loss |
| Attacco singolo (h3) | bloccato solo l'attaccante | h3 bloccato, legittimi liberi |
| Attacco distribuito (h3,h5,h9,h12) | attaccanti bloccati | tipicamente 3 su 4 bloccati, legittimi liberi |

Nell'attacco distribuito il sistema blocca stabilmente la maggioranza delle
sorgenti (tipicamente 3 su 4), abbattendo il volume aggregato dell'attacco sotto
la soglia di saturazione: l'attacco viene così neutralizzato e il server torna a
gestire il carico. In tutti gli scenari **nessun host legittimo viene bloccato**.

Esiste un compromesso, coerente con la natura del problema: poiché nel caso
distribuito il rate degli attaccanti e quello dei legittimi si sovrappongono,
durante l'attacco qualche flusso legittimo può occasionalmente essere segnalato
come sospetto. Grazie al contatore di conferme (`SUSPICIOUS_LIMIT = 4`) queste
segnalazioni isolate **non si traducono in un blocco**: un host legittimo può
avvicinarsi alla soglia ma non la raggiunge, mentre un attaccante, che genera
sospetto in modo continuo, la supera. Il valore 4 è il giusto compromesso tra
rapidità di blocco degli attaccanti e protezione dei legittimi.

---

## Limiti e sviluppi futuri

Il sistema è progettato e validato per il rilevamento di attacchi flood UDP,
singoli e distribuiti; l'estensione ad altri protocolli (TCP, ICMP) e ad altre
classi di attacco è un possibile sviluppo futuro. Nei primi secondi di un
attacco può esserci un breve transitorio prima che il controller completi le
quattro conferme: è un comportamento voluto, che evita blocchi impulsivi al primo
campione. Ulteriori sviluppi: soglia adattiva, classificazione multiclasse del
tipo di attacco, whitelist esterna configurabile e più topologie di test.

---

## Guida rapida passo-passo

Riepilogo operativo di tutti i comandi, in ordine, per chi vuole eseguire il
progetto da zero.

### 1) Rigenerare dataset e modello (un comando)

```bash
cd ~/Scrivania/DDOS_progetto
chmod +x run_collect.sh
sudo -E ./run_collect.sh
```

Al termine si ottengono `dataset/dataset_v8_training.csv`, `ml/best_model.joblib`
e `results/model_report.txt`. Per una prova rapida: `ROUNDS=2 PHASE_SECONDS=45 sudo -E ./run_collect.sh`.
Per riaddestrare soltanto: `python3 train_model.py`.

### 2) Verificare l'addestramento

Aprire `results/model_report.txt` e controllare che le metriche siano realistiche
(intorno a 0.97, non 1.0) e che la baseline `if(packet_rate)` abbia F1 molto più
basso del modello: è la prova che il Machine Learning è necessario.

### 3) Testare la mitigazione (due terminali + uno di servizio)

Preparazione, nella shell normale:

```bash
sudo rm -f /tmp/h4_sink.log /tmp/snd_*.log /tmp/controller_log.txt
sudo mn -c
cp scripts/udp_realistic_sender.py scripts/udp_sink.py /tmp/
```

Terminale 1 (controller, con log su file):

```bash
cd ~/Scrivania/DDOS_progetto
PYTHONPATH=./ryu python3 ryu/bin/ryu-manager controller/ml_detector_controller_final.py 2>&1 | tee /tmp/controller_log.txt
```

Terminale 2 (topologia):

```bash
cd ~/Scrivania/DDOS_progetto
sudo -E python3 topology/network_core_access.py
```

Dentro `mininet>`, scegliere un test:

```bash
source scripts/test_in_mininet/verify_1_legittimo.mn
source scripts/test_in_mininet/verify_2_singolo.mn
source scripts/test_in_mininet/verify_3_distribuito.mn
source scripts/test_in_mininet/verify_full.mn
```

#### I quattro test in dettaglio

Ogni test si lancia dal prompt `mininet>` con `source` e verifica uno scenario
diverso. Prima di ognuno vanno copiati sender e sink in `/tmp` (vedi sopra) e,
tra un test e l'altro, conviene ripulire con `exit` + `sudo mn -c`.

- **`verify_1_legittimo.mn`** — solo traffico legittimo (h1, h2, h8) verso h4.
  Serve a verificare l'assenza di falsi positivi: atteso nessun blocco e tutti i
  ping a 0% loss.

  ```bash
  source scripts/test_in_mininet/verify_1_legittimo.mn
  ```

- **`verify_2_singolo.mn`** — attacco DoS volumetrico da una sola sorgente (h3 ad
  alto rate) con traffico legittimo di sottofondo. Atteso: bloccato solo h3, i
  legittimi restano liberi.

  ```bash
  source scripts/test_in_mininet/verify_2_singolo.mn
  ```

- **`verify_3_distribuito.mn`** — attacco DDoS distribuito coordinato (h3, h5, h9,
  h12 a rate basso e sovrapposto ai legittimi) con traffico legittimo di
  sottofondo. Atteso: bloccati gli attaccanti (tipicamente 3 su 4, sufficienti a
  neutralizzare l'attacco), legittimi liberi.

  ```bash
  source scripts/test_in_mininet/verify_3_distribuito.mn
  ```

- **`verify_full.mn`** — le tre fasi in sequenza (normale → singolo → distribuito)
  con pause intermedie, per osservare il comportamento della rete che passa da
  traffico normale a sotto attacco senza azzerarsi. I blocchi si accumulano tra
  le fasi (durata regola DROP 300 s).

  ```bash
  source scripts/test_in_mininet/verify_full.mn
  ```

**Test di connettività della rete (opzionale).** Per verificare che tutti gli
host si raggiungano, dal prompt `mininet>` basta:

```bash
pingall
```

Il primo `pingall` a rete appena avviata può mostrare qualche pacchetto perso
finché gli switch non imparano gli indirizzi MAC: rilanciarlo una seconda volta,
il risultato atteso è `0% dropped`.

Estrazione dei risultati (shell normale, dopo `exit` da Mininet):

```bash
grep "BLOCCO" /tmp/controller_log.txt
grep "sospetto" /tmp/controller_log.txt | grep -oE "10.0.0.[0-9]+ -> 10.0.0.4: conteggio [0-9]/4" | sort | uniq -c
```

### Note pratiche

- I comandi che iniziano con `h1`, `h4`, `sh`, `source` funzionano solo dentro la
  CLI di Mininet (prompt `mininet>`); il `cp` va fatto nella shell normale.
- Tra un test e l'altro eseguire `exit` e `sudo mn -c`: le regole DROP durano 300
  secondi e resterebbero attive nel test successivo.
- I file in `/tmp` sono temporanei e si azzerano al riavvio della macchina; se un
  log serve per la documentazione, copiarlo in `results/`.