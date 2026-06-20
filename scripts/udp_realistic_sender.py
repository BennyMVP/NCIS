import socket
import time
import random
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--dst", required=True)
parser.add_argument("--port", type=int, required=True)
parser.add_argument("--duration", type=float, default=60)
parser.add_argument("--pps-min", type=float, default=20)
parser.add_argument("--pps-max", type=float, default=150)
parser.add_argument("--payload-min", type=int, default=100)
parser.add_argument("--payload-max", type=int, default=900)
parser.add_argument("--start-delay", type=float, default=0)
parser.add_argument("--burst-prob", type=float, default=0.10)
parser.add_argument("--burst-min", type=int, default=5)
parser.add_argument("--burst-max", type=int, default=40)
parser.add_argument("--sleep-jitter", type=float, default=0.005)
args = parser.parse_args()

time.sleep(args.start_delay)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
target = (args.dst, args.port)
end = time.time() + args.duration

while time.time() < end:
    pps = random.uniform(args.pps_min, args.pps_max)
    payload_size = random.randint(args.payload_min, args.payload_max)
    payload = random.randbytes(payload_size) if hasattr(random, "randbytes") else bytes(random.getrandbits(8) for _ in range(payload_size))

    # traffico normale: un pacchetto
    packets = 1

    # ogni tanto burst breve, più realistico di un flusso costante
    if random.random() < args.burst_prob:
        packets = random.randint(args.burst_min, args.burst_max)

    for _ in range(packets):
        sock.sendto(payload, target)

    sleep_time = max(0.001, (1.0 / pps) + random.uniform(-args.sleep_jitter, args.sleep_jitter))
    time.sleep(sleep_time)
