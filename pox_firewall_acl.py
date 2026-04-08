# Task 1: Firewall
#
# This POX controller acts as a simple software-defined firewall.
# It inspects incoming packets sent to the controller by the OpenFlow switch
# and decides whether traffic should be forwarded or blocked.
#
# The filtering logic is implemented as a static ACL (Access Control List).
# Static means that the rules are fixed in code and are not learned or updated
# dynamically at runtime.
#
# The intended policy for this exercise is:
# - Allow HTTP traffic to and from host h2
# - Allow SSH traffic between h1 and h2
# - Block all other IP traffic

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, ipv4, tcp, udp, icmp
from pox.lib.addresses import IPAddr

# POX logger used for status output and debugging information in the controller.
log = core.getLogger()

class SimpleFirewall (object):
    def __init__(self, connection):
        # Store the switch connection object so the controller can later
        # install flow rules on that specific switch.
        self.connection = connection

        # Register this object as a listener for OpenFlow events such as
        # PacketIn, which is triggered when the switch forwards a packet to
        # the controller for inspection.
        connection.addListeners(self)

        # Log that the controller logic has been attached to the switch.
        log.info("Firewall controller connected with %s", connection)

    def _handle_PacketIn(self, event):
        # The parsed Ethernet frame received from the switch.
        packet = event.parsed

        # If POX could not parse the packet correctly, do not continue with
        # ACL processing because important header fields may be missing.
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        # Try to locate an IPv4 packet inside the Ethernet frame.
        # Non-IP traffic such as ARP is not filtered by this firewall and is
        # forwarded to keep basic network communication functional.
        ip_packet = packet.find('ipv4')
        if ip_packet is None:
            # Not an IP packet, for example ARP. Allow it to pass.
            self._allow_packet(event)
            return

        # Extract the fields that are relevant for ACL evaluation.
        # These values are enough to implement a simple layer-3/layer-4 policy:
        # source IP, destination IP, IP protocol number, and transport ports.
        src_ip = ip_packet.srcip
        dst_ip = ip_packet.dstip
        proto = ip_packet.protocol

        # Initialize ports with None because not every IP protocol contains
        # transport-layer port numbers.
        src_port = None
        dst_port = None

        if proto == ipv4.ICMP_PROTOCOL:
            # ICMP does not use source/destination ports.
            pass
        elif proto == ipv4.TCP_PROTOCOL:
            # For TCP traffic, extract source and destination ports so that the
            # ACL can distinguish protocols such as HTTP or SSH.
            tcp_packet = packet.find('tcp')
            if tcp_packet:
                src_port = tcp_packet.srcport
                dst_port = tcp_packet.dstport
        elif proto == ipv4.UDP_PROTOCOL:
            # For UDP traffic, extract the port information in the same way.
            udp_packet = packet.find('udp')
            if udp_packet:
                src_port = udp_packet.srcport
                dst_port = udp_packet.dstport

        # Apply the ACL decision.
        # If the packet matches a blocking rule, do nothing, which effectively
        # drops it. Otherwise, install a forwarding rule and let it pass.
        if self.is_blocked(src_ip, dst_ip, proto, dst_port):
            log.info("Blocked: %s -> %s (proto %s, port %s)", src_ip, dst_ip, proto, dst_port)
            return  # The packet is intentionally not forwarded.
        else:
            log.info("Allowed: %s -> %s (proto %s, port %s)", src_ip, dst_ip, proto, dst_port)
            self._allow_packet(event)

    # Static ACL implementation.
    #
    # The method should return True if a packet must be blocked and False if it
    # should be allowed. The controller currently calls this method with the
    # source IP, destination IP, IP protocol, and destination port.
    #
    # TODO: Define your ACL rules in the "is_blocked" method.
    """
    # --- Help ---
    # Examples for comparing common IP protocol values:
    proto == ipv4.TCP_PROTOCOL
    proto == ipv4.UDP_PROTOCOL
    proto == ipv4.ICMP_PROTOCOL
    proto == ipv4.IGMP_PROTOCOL

    # Example for comparing an IP address:
    ip == IPAddr("192.168.0.1")

    # Example for checking whether an IP address belongs to a subnet:
    if ip.inNetwork("192.168.1.0/24"):
        print("Address is in the subnet")
    """
    def is_blocked(self, src, dst, proto, dport):
        # Define the ACL rules here using conditions such as protocol numbers,
        # IP addresses, or port numbers.
        #
        # General pattern:
        # if <condition> and <additional condition>:
        #     return True   # True means: block packet
        #
        # If no blocking rule matches, return False to allow the packet.



        return False

    def _allow_packet(self, event):
        # Install a flow entry on the switch so that matching packets are
        # forwarded directly by the switch without sending every packet back to
        # the controller.
        msg = of.ofp_flow_mod()

        # Build a flow match based on the packet headers of the current packet.
        msg.match = of.ofp_match.from_packet(event.parsed)

        # Remove the rule after 30 seconds of inactivity.
        msg.idle_timeout = 30

        # Flood the packet out of all switch ports except the incoming one.
        # This is acceptable for a small lab topology, although real networks
        # would usually use more specific forwarding behavior.
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))

        # Attach the original packet so the first packet of the flow is also
        # forwarded immediately.
        msg.data = event.ofp

        # Send the flow modification message to the switch.
        self.connection.send(msg)

def launch():
    def start_switch(event):
        # Create one firewall controller instance per switch connection.
        log.info("Starting firewall on %s", event.connection)
        SimpleFirewall(event.connection)

    # Register the callback that is executed whenever a switch connects to POX.
    core.openflow.addListenerByName("ConnectionUp", start_switch)
