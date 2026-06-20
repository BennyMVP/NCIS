#!/usr/bin/python3
# =============================================================================
# auto_collect.py - Topologia core/access AUTOMATICA per la raccolta dataset.
#
# A differenza di network_core_access.py (che apre la CLI interattiva), questo
# script esegue DA SOLO tutte le fasi di traffico, scrive l'etichetta corrente
# nel file /tmp/current_label.txt (che il collector legge) e alla fine chiude.
#
# Fasi eseguite, ripetute ROUNDS volte:
#   - NORMALE            (label 0)
#   - ATTACCO DISTRIBUITO(label 1)
#   - ATTACCO SINGOLO    (label 1)
#
# Ogni fase usa una SESSION distinta (es. normale_r1, attacco_distribuito_r2...)
# Ogni round impiega identificativi di sessione distinti, per una suddivisione train/test rappresentativa.
#
# Va lanciato con sudo, MENTRE il collector gira in background (lo fa lo script
# run_collect.sh). Il collector scrive direttamente dataset/dataset_v8_training.csv
# accodando tutte le righe di tutte le fasi e di tutti i round.
# =============================================================================

import os
import time
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info

SENDER = "/tmp/udp_realistic_sender.py"
VICTIM = "10.0.0.4"
LABEL_FILE = "/tmp/current_label.txt"

# quante volte ripetere il ciclo completo (normale+distribuito+singolo)
ROUNDS = int(os.environ.get("ROUNDS", "3"))
# durata di ogni fase in secondi
PHASE_SECONDS = int(os.environ.get("PHASE_SECONDS", "60"))
# Intervallo di transizione tra le fasi (assenza di registrazione)
PAUSE_SECONDS = 6


def set_label(label, session_id):
    """Scrive (o rimuove) l'etichetta che il collector legge."""
    if label is None:
        if os.path.exists(LABEL_FILE):
            os.remove(LABEL_FILE)
        info("*** [LABEL] fase vuota\n")
    else:
        with open(LABEL_FILE, "w") as f:
            f.write(f"{label};{session_id}")
        info(f"*** [LABEL] label={label} session={session_id}\n")


def build_net():
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True)
    c0 = net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)

    s0 = net.addSwitch("s0", protocols="OpenFlow13")
    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    s2 = net.addSwitch("s2", protocols="OpenFlow13")
    s3 = net.addSwitch("s3", protocols="OpenFlow13")
    s4 = net.addSwitch("s4", protocols="OpenFlow13")

    hosts = {}
    for i in range(1, 13):
        hosts[f"h{i}"] = net.addHost(f"h{i}", ip=f"10.0.0.{i}/24")

    for h, s in [("h1", s1), ("h2", s1), ("h3", s1),
                 ("h4", s2), ("h5", s2), ("h6", s2),
                 ("h7", s3), ("h8", s3), ("h9", s3),
                 ("h10", s4), ("h11", s4), ("h12", s4)]:
        net.addLink(hosts[h], s, bw=10, delay="5ms")

    for s in [s1, s2, s3, s4]:
        net.addLink(s, s0, bw=10, delay="5ms")

    net.build()
    c0.start()
    for s in [s0, s1, s2, s3, s4]:
        s.start([c0])

    return net, hosts


def stop_traffic(hosts):
    """Ferma ogni traffico residuo sugli host."""
    for h in hosts.values():
        h.cmd("kill %python3 2>/dev/null")
        h.cmd("pkill -f udp_realistic_sender 2>/dev/null")
        h.cmd("pkill iperf3 2>/dev/null")
    time.sleep(1)


def snd(host, port, dur, pmin, pmax, paymin=100, paymax=900, delay=0, burst=0.10):
    """Costruisce il comando del sender."""
    return (f"timeout {dur+10} python3 {SENDER} --dst {VICTIM} --port {port} "
            f"--duration {dur} --pps-min {pmin} --pps-max {pmax} "
            f"--payload-min {paymin} --payload-max {paymax} "
            f"--start-delay {delay} --burst-prob {burst} > /tmp/snd_{host.name}_{port}.log 2>&1 &")


def phase_normale(hosts, dur, sess):
    set_label(0, sess)
    h = hosts
    h["h4"].cmd("iperf3 -s > /tmp/h4_s.log 2>&1 &")
    # traffico legittimo a basso rate, poche sorgenti
    h["h1"].cmd(snd(h["h1"], 8888, dur, 5, 25, 80, 300, 1, 0.03))
    h["h2"].cmd(snd(h["h2"], 8889, dur, 5, 20, 80, 250, 3, 0.02))
    h["h8"].cmd(snd(h["h8"], 8890, dur, 8, 30, 100, 350, 5, 0.04))
    time.sleep(dur)


def phase_distribuito(hosts, dur, sess):
    set_label(1, sess)
    h = hosts
    h["h4"].cmd("iperf3 -s > /tmp/h4_s.log 2>&1 &")
    # 8 sorgenti low-rate distribuite su switch diversi
    attackers = [("h3", 9999, 40, 160), ("h5", 9998, 35, 140), ("h6", 9997, 50, 180),
                 ("h7", 9996, 45, 170), ("h9", 9995, 35, 150), ("h10", 9994, 45, 170),
                 ("h11", 9993, 40, 160), ("h12", 9992, 50, 180)]
    for i, (name, port, pmin, pmax) in enumerate(attackers):
        h[name].cmd(snd(h[name], port, dur, pmin, pmax, 250, 900, 6 + i*2, 0.14))
    # traffico legittimo concorrente
    h["h1"].cmd(snd(h["h1"], 8888, dur, 5, 25, 80, 300, 1, 0.03))
    h["h2"].cmd(snd(h["h2"], 8889, dur, 5, 20, 80, 250, 3, 0.02))
    time.sleep(dur)


def phase_singolo(hosts, dur, sess):
    set_label(1, sess)
    h = hosts
    h["h4"].cmd("iperf3 -s > /tmp/h4_s.log 2>&1 &")
    # un solo attaccante ad alto rate
    h["h3"].cmd(snd(h["h3"], 9999, dur, 250, 450, 600, 1200, 2, 0.20))
    # legittimo concorrente
    h["h1"].cmd(snd(h["h1"], 8888, dur, 5, 25, 80, 300, 1, 0.03))
    h["h2"].cmd(snd(h["h2"], 8889, dur, 5, 20, 80, 250, 3, 0.02))
    time.sleep(dur)


def run():
    set_label(None, None)
    net, hosts = build_net()
    info("*** Rete avviata. Attendo connessione switch...\n")
    time.sleep(5)

    for r in range(1, ROUNDS + 1):
        info(f"\n========== ROUND {r}/{ROUNDS} ==========\n")

        info("--- FASE NORMALE ---\n")
        phase_normale(hosts, PHASE_SECONDS, f"normale_r{r}")
        set_label(None, None); stop_traffic(hosts); time.sleep(PAUSE_SECONDS)

        info("--- FASE ATTACCO DISTRIBUITO ---\n")
        phase_distribuito(hosts, PHASE_SECONDS, f"attacco_distribuito_r{r}")
        set_label(None, None); stop_traffic(hosts); time.sleep(PAUSE_SECONDS)

        info("--- FASE ATTACCO SINGOLO ---\n")
        phase_singolo(hosts, PHASE_SECONDS, f"attacco_singolo_r{r}")
        set_label(None, None); stop_traffic(hosts); time.sleep(PAUSE_SECONDS)

    info("\n*** Raccolta completata. Arresto rete.\n")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run()
