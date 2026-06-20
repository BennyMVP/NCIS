#!/usr/bin/python3

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info


def run():
    net = Mininet(
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )

    info("*** Aggiunta controller remoto Ryu\n")
    c0 = net.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6653
    )

    info("*** Aggiunta switch core/access\n")

    # Switch principale centrale
    s0 = net.addSwitch("s0", protocols="OpenFlow13")

    # Switch access
    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    s2 = net.addSwitch("s2", protocols="OpenFlow13")
    s3 = net.addSwitch("s3", protocols="OpenFlow13")
    s4 = net.addSwitch("s4", protocols="OpenFlow13")

    info("*** Aggiunta host\n")

    # s1: h1 h2 h3
    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24")
    h3 = net.addHost("h3", ip="10.0.0.3/24")

    # s2: h4 h5 h6
    # h4 è la vittima
    h4 = net.addHost("h4", ip="10.0.0.4/24")
    h5 = net.addHost("h5", ip="10.0.0.5/24")
    h6 = net.addHost("h6", ip="10.0.0.6/24")

    # s3: h7 h8 h9
    h7 = net.addHost("h7", ip="10.0.0.7/24")
    h8 = net.addHost("h8", ip="10.0.0.8/24")
    h9 = net.addHost("h9", ip="10.0.0.9/24")

    # s4: h10 h11 h12
    h10 = net.addHost("h10", ip="10.0.0.10/24")
    h11 = net.addHost("h11", ip="10.0.0.11/24")
    h12 = net.addHost("h12", ip="10.0.0.12/24")

    info("*** Collegamento host agli switch access\n")

    # Host su s1
    net.addLink(h1, s1, bw=10, delay="5ms")
    net.addLink(h2, s1, bw=10, delay="5ms")
    net.addLink(h3, s1, bw=10, delay="5ms")

    # Host su s2
    net.addLink(h4, s2, bw=10, delay="5ms")
    net.addLink(h5, s2, bw=10, delay="5ms")
    net.addLink(h6, s2, bw=10, delay="5ms")

    # Host su s3
    net.addLink(h7, s3, bw=10, delay="5ms")
    net.addLink(h8, s3, bw=10, delay="5ms")
    net.addLink(h9, s3, bw=10, delay="5ms")

    # Host su s4
    net.addLink(h10, s4, bw=10, delay="5ms")
    net.addLink(h11, s4, bw=10, delay="5ms")
    net.addLink(h12, s4, bw=10, delay="5ms")

    info("*** Collegamento switch access allo switch centrale s0\n")

    net.addLink(s1, s0, bw=10, delay="5ms")
    net.addLink(s2, s0, bw=10, delay="5ms")
    net.addLink(s3, s0, bw=10, delay="5ms")
    net.addLink(s4, s0, bw=10, delay="5ms")

    info("*** Costruzione rete\n")
    net.build()

    info("*** Avvio controller e switch\n")
    c0.start()

    s0.start([c0])
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])
    s4.start([c0])

    info("\n*** Topologia core/access avviata correttamente\n")
    info("*** s0: switch centrale/core\n")
    info("*** s1: h1, h2, h3\n")
    info("*** s2: h4, h5, h6   --> h4 vittima 10.0.0.4\n")
    info("*** s3: h7, h8, h9\n")
    info("*** s4: h10, h11, h12\n")
    info("*** Attacco distribuito: host di switch diversi -> s0 -> s2 -> h4\n\n")

    CLI(net)

    info("*** Arresto rete\n")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run()
