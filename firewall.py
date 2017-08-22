import os
from pox.core import core
import pox.openflow.libopenflow_01 as openflow
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr, IPAddr
import pox.lib.packet as packet
from collections import namedtuple

log = core.getLogger()
n=raw_input('no of entries in the table')
ip_table = []
for i in range(int(n)):
    ip_table.append([raw_input('src ip'),raw_input('dst ip')])

class Firewall(EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        self.firewall = {}

    # Applies the rule
    def apply_rule (self, src, dst, duration = 0):
        if not isinstance(duration, tuple):
            duration = (duration,duration)
        msg = openflow.ofp_flow_mod()
	match = openflow.ofp_match(dl_type = 0x800,
			     nw_proto = packet.ipv4.ICMP_PROTOCOL)
        match.nw_src = IPAddr(src)
        match.nw_dst = IPAddr(dst)
        msg.match = match
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.priority = 10
        self.connection.send(msg)
	log.info("Rule Applied drop: src %s - dst %s", src, dst)

    # function for adding rules into the firewall table
    def add_rule(self, src=0, dst=0, value=True):
	if src == None and dst == None:
	    return
        if (src, dst) in self.firewall:
            log.info("Rule already present drop: src %s - dst %s", src, dst)
        else:
            log.info("Adding firewall rule drop: src %s - dst %s", src, dst)
            self.firewall[(src, dst)]=value
            self.apply_rule(src, dst, 10000)

    # Manages the connection
    def _handle_ConnectionUp(self, event):
        self.connection = event.connection
	header = ['id', 'ip_0', 'ip_1']
	for ip_list in ip_table:
	    self.add_rule(ip_list[0], ip_list[1])
        log.info("Firewall rules installed on %s", dpidToStr(event.dpid))

def main():
    print "in main"
    core.registerNew(Firewall)

main()

