# Mininet topology for Task 2: Firewall with subnets
# Clients are in different /24 subnets (netmask set to /16 to avoid routing)

from mininet.topo import Topo

class SDNFirewallTopo(Topo):
    def build(self):
        # Switch
        s1 = self.addSwitch('s1')

        # Hosts
        # netmask set to /16 to avoid routing
        h1 = self.addHost('h1', ip='10.0.1.1/16')  # internal client
        h2 = self.addHost('h2', ip='10.0.2.2/16')  # server in "DMZ"
        h3 = self.addHost('h3', ip='10.0.3.3/16')  # external client
        h4 = self.addHost('h4', ip='10.0.2.4/16')  # Client in "DMZ"

        # Links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)

topos = { 'sdnfirewall': (lambda: SDNFirewallTopo()) }
