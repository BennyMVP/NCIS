
import os
import time
import random
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info

SENDER = "/tmp/udp_realistic_sender.py"
SINK = "/tmp/udp_sink.py"
VICTIM = "10.0.0.4"
LABEL_FILE = "/tmp/current_label.txt"

ROUNDS = int(os.environ.get("ROUNDS", "5"))
PHASE_SECONDS = int(os.environ.get("PHASE_SECONDS", "60"))
PAUSE_SECONDS = 6

# range di porte che h4 tiene aperte col sink (coprono legittimi e attaccanti,
# con margine per gli offset di round pofs = r*1000 ... in realta' rebindiamo
# il sink ad ogni fase sulle porte di quel round, vedi open_sink()).
LEGIT_PORT_BASE = 8800
ATTACK_PORT_BASE = 9900

# --- profili comportamentali (payload in byte) -------------------------------
# LEGITTIMO: payload molto variabili (traffico applicativo eterogeneo)
LEG_PAY_LOW, LEG_PAY_HIGH = 200, 1400
# ATTACCANTE: payload piu' uniformi (flood macchina), ma range che si SOVRAPPONE
# a quello legittimo cosi' nemmeno la dimensione media e' un separatore pulito.
ATK_PAY_LOW, ATK_PAY_HIGH = 300, 800


def host_ip(host_name):
    return "10.0.0." + host_name[1:]


def rr(lo, hi):
    """Estrae un sotto-range [a,b] dentro [lo,hi] per dare varieta' fra host."""
    a = random.uniform(lo, (lo + hi) / 2.0)
    b = random.uniform((lo + hi) / 2.0, hi)
    return int(round(a)), int(round(b))


def set_label(label, session_id, attacker_ips=None):
    if label is None:
        if os.path.exists(LABEL_FILE):
            os.remove(LABEL_FILE)
        info("*** [LABEL] fase vuota\n")
    else:
        line = f"{label};{session_id}"
        if attacker_ips:
            line += ";" + ",".join(attacker_ips)
        with open(LABEL_FILE, "w") as f:
            f.write(line)
        info(f"*** [LABEL] label={label} session={session_id} "
             f"attaccanti={sorted(attacker_ips) if attacker_ips else '-'}\n")


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


def open_sink(hosts, pofs):
    """Avvia su h4 il listener UDP su tutte le porte usate in questo round.
    Cosi' nessun pacchetto UDP finisce su porta chiusa e NON viene generato
    alcun ICMP port-unreachable."""
    lo_leg = LEGIT_PORT_BASE + pofs
    hi_leg = LEGIT_PORT_BASE + pofs + 99
    lo_atk = ATTACK_PORT_BASE + pofs
    hi_atk = ATTACK_PORT_BASE + pofs + 99
    ports = f"{lo_leg}-{hi_leg},{lo_atk}-{hi_atk}"
    hosts["h4"].cmd(f"pkill -f udp_sink 2>/dev/null")
    hosts["h4"].cmd(f"python3 {SINK} --ports {ports} > /tmp/h4_sink.log 2>&1 &")
    time.sleep(1)


def stop_traffic(hosts):
    for h in hosts.values():
        h.cmd("pkill -f udp_realistic_sender 2>/dev/null")
    time.sleep(2)


def snd(host, port, dur, pmin, pmax, paymin, paymax,
        delay, burst, burst_min, burst_max, jitter):
    """Comando sender con profilo comportamentale completo."""
    return (f"timeout {dur+10} python3 {SENDER} --dst {VICTIM} --port {port} "
            f"--duration {dur} --pps-min {pmin} --pps-max {pmax} "
            f"--payload-min {paymin} --payload-max {paymax} "
            f"--start-delay {delay} --burst-prob {burst} "
            f"--burst-min {burst_min} --burst-max {burst_max} "
            f"--sleep-jitter {jitter} "
            f"> /tmp/snd_{host.name}_{port}.log 2>&1 &")


# --- profilo LEGITTIMO: timing irregolare, payload ampi, burst umani rari -----
def legit_sender(h, name, port, dur, delay):
    pmin, pmax = rr(5, 38)                       # rate sovrapposto agli attacchi
    burst = round(random.uniform(0.05, 0.09), 3)  # burst umani occasionali
    jitter = round(random.uniform(0.020, 0.045), 4)  # timing IRREGOLARE
    h[name].cmd(snd(h[name], port, dur, pmin, pmax,
                    LEG_PAY_LOW, LEG_PAY_HIGH,
                    delay=delay, burst=burst, burst_min=4, burst_max=14,
                    jitter=jitter))


# --- profilo ATTACCANTE: timing regolare, payload uniformi, sciame coordinato -
def attack_sender(h, name, port, dur, delay):
    pmin, pmax = rr(10, 38)                      # STESSO range di pps dei legit
    burst = round(random.uniform(0.00, 0.03), 3)  # quasi nessun burst: steady
    jitter = round(random.uniform(0.001, 0.003), 4)  # timing MOLTO REGOLARE
    h[name].cmd(snd(h[name], port, dur, pmin, pmax,
                    ATK_PAY_LOW, ATK_PAY_HIGH,
                    delay=delay, burst=burst, burst_min=2, burst_max=5,
                    jitter=jitter))


# 7 sorgenti legittime distribuite su tutti gli switch di accesso
LEGIT_HOSTS = [("h1", 0), ("h2", 1), ("h6", 2), ("h7", 3),
               ("h8", 4), ("h10", 5), ("h11", 6)]
# 4 attaccanti, uno per switch (attacco distribuito), sincronizzati
ATTACK_HOSTS = ["h3", "h5", "h9", "h12"]


def phase_normale(hosts, dur, sess, pofs):
    set_label(0, sess)
    open_sink(hosts, pofs)
    for name, idx in LEGIT_HOSTS:
        legit_sender(hosts, name, LEGIT_PORT_BASE + pofs + idx, dur,
                     delay=round(random.uniform(0.5, 4.0), 2))
    time.sleep(dur)


def phase_distribuito(hosts, dur, sess, pofs):
    open_sink(hosts, pofs)
    attacker_ips = [host_ip(n) for n in ATTACK_HOSTS]
    set_label(1, sess, attacker_ips)

    # traffico legittimo di sottofondo (stesso profilo della fase normale):
    # serve perche' durante l'attacco il modello deve distinguere il flusso
    # legittimo da quello d'attacco DENTRO lo stesso contesto aggregato.
    for name, idx in LEGIT_HOSTS:
        legit_sender(hosts, name, LEGIT_PORT_BASE + pofs + idx, dur,
                     delay=round(random.uniform(0.5, 4.0), 2))

    # attaccanti SINCRONIZZATI: partono quasi insieme (coordinamento -> lo
    # sciame appare in contemporanea sulla vittima, segnale aggregato forte).
    for i, name in enumerate(ATTACK_HOSTS):
        attack_sender(hosts, name, ATTACK_PORT_BASE + pofs + i, dur,
                      delay=round(3 + random.uniform(0.0, 1.5), 2))
    time.sleep(dur)


def phase_singolo(hosts, dur, sess, pofs):
    """DoS classico da singola sorgente ad alto rate: qui l'attaccante NON si
    nasconde (rate alto), utile come contrasto rispetto al distribuito low-rate.
    Il segnale e' volumetrico, non di coordinamento."""
    open_sink(hosts, pofs)
    set_label(1, sess, [host_ip("h3")])

    # attaccante singolo ad alto rate (volumetrico, ben distinguibile)
    pmin, pmax = rr(200, 420)
    hosts["h3"].cmd(snd(hosts["h3"], ATTACK_PORT_BASE + pofs, dur, pmin, pmax,
                        ATK_PAY_LOW, ATK_PAY_HIGH, delay=2,
                        burst=round(random.uniform(0.15, 0.22), 3),
                        burst_min=20, burst_max=60,
                        jitter=round(random.uniform(0.001, 0.003), 4)))

    # sottofondo legittimo
    for name, idx in [("h1", 0), ("h2", 1), ("h8", 4)]:
        legit_sender(hosts, name, LEGIT_PORT_BASE + pofs + idx, dur,
                     delay=round(random.uniform(0.5, 3.0), 2))
    time.sleep(dur)


def run():
    set_label(None, None)
    net, hosts = build_net()
    info("*** Rete avviata. Attendo connessione switch...\n")
    time.sleep(5)

    for r in range(1, ROUNDS + 1):
        random.seed(1000 + r)
        pofs = r * 1000
        info(f"\n========== ROUND {r}/{ROUNDS} ==========\n")

        info("--- FASE NORMALE ---\n")
        phase_normale(hosts, PHASE_SECONDS, f"normale_r{r}", pofs)
        set_label(None, None); stop_traffic(hosts); time.sleep(PAUSE_SECONDS)

        info("--- FASE ATTACCO DISTRIBUITO (low-rate, coordinato) ---\n")
        phase_distribuito(hosts, PHASE_SECONDS, f"attacco_distribuito_r{r}", pofs)
        set_label(None, None); stop_traffic(hosts); time.sleep(PAUSE_SECONDS)

        info("--- FASE ATTACCO SINGOLO (volumetrico) ---\n")
        phase_singolo(hosts, PHASE_SECONDS, f"attacco_singolo_r{r}", pofs)
        set_label(None, None); stop_traffic(hosts); time.sleep(PAUSE_SECONDS)

    info("\n*** Raccolta completata. Arresto rete.\n")
    hosts["h4"].cmd("pkill -f udp_sink 2>/dev/null")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run()
