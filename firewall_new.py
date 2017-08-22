import os
import thread
from pox.core import core
import pox.openflow.libopenflow_01 as openflow
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr, IPAddr
import pox.lib.packet as packet
from collections import namedtuple

log = core.getLogger()

ip_table = []
def input_ip():
    global n
    n=raw_input('no of entries in the table: ')
    global ip_table
    global s_ip
    global d_ip
    global proto
    global d_port
    d_port=0
    for i in range(int(n)):
	s_ip = raw_input('src ip: ')
	d_ip = raw_input('dst ip: ')
	proto = raw_input('protocol(tcp/udp/icmp): ')
    	if proto not in ["icmp"]:
	    port = raw_input('dst port: ')
	    if port == None or port == '':
	        d_port = 0
	    else:
	        d_port = int(port)
        ip_table.append([ s_ip, d_ip, proto, d_port ])

class Firewall(EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        self.firewall = {}

    # Applies the rule
    def apply_rule (self, src, dst, proto, dst_port, duration = 0):
        if not isinstance(duration, tuple):
            duration = (duration,duration)
        msg = openflow.ofp_flow_mod()
	match = openflow.ofp_match(dl_type = 0x800,
			     nw_proto = proto )
        match.nw_src = IPAddr(src)
        match.nw_dst = IPAddr(dst)
	if proto == 6 or proto == 17 :
            match.tp_dst = dst_port
            #match.tp_src = 8632
        msg.match = match
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.priority = 10
	print msg
        self.connection.send(msg)
	log.info("Rule Applied drop: src %s - dst %s", src, dst)

    # function for adding rules into the firewall table
    def AddRule(self, src=0, dst=0, pr=1, dst_port=0, value=True):
	if src == None and dst == None:
	    return
	if pr == 'tcp' :
	    proto = 6
	elif pr == 'udp' :
	    proto = 17
	else:
	    proto = 1
        if (src, dst) in self.firewall:
            log.info("Rule already present drop: src %s - dst %s", src, dst)
        else:
            log.info("Adding firewall rule drop: src %s - dst %s", src, dst)
            self.firewall[(src, dst, dst_port, proto)]=value
            self.apply_rule(src, dst, proto, dst_port, 10000)

    # Manages the connection
    def _handle_ConnectionUp(self, event):
        self.connection = event.connection
	header = ['id', 'ip_0', 'ip_1']
	for ip_list in ip_table:
	    self.AddRule(ip_list[0], ip_list[1], ip_list[2], ip_list[3])
        log.info("Firewall rules installed on %s", dpidToStr(event.dpid))

def main():
    input_ip()
    print "in main"
    core.registerNew(Firewall)

main()

