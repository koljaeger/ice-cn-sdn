# Mininet topology for Task 1: Firewall
# All clients are in the same /24 subnet, and the switch is connected to all hosts.

from mininet.topo import Topo

class SDNFirewallTopo(Topo):
    def build(self):
        # Switch
        s1 = self.addSwitch('s1')

        # Hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24')  # internal client
        h2 = self.addHost('h2', ip='10.0.0.2/24')  # server
        h3 = self.addHost('h3', ip='10.0.0.3/24')  # external client

        # Links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)

topos = { 'sdnfirewall': (lambda: SDNFirewallTopo()) }
