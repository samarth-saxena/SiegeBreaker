# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4

class SimpleSwitch13(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(SimpleSwitch13, self).__init__(*args, **kwargs)
		self.mac_to_port = {}

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		print ('Initializing switch')

		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# install table-miss flow entry
		#
		# We specify NO BUFFER to max_len of the output action due to
		# OVS bug. At this moment, if we specify a lesser number, e.g.,
		# 128, OVS will send Packet-In with invalid buffer_id and
		# truncated packet data. In that case, we cannot output packets
		# correctly.  The bug has been fixed in OVS v2.1.0.
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										  ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)

		inst = []
			# match1 = parser.OFPMatch(ipv4_src=src_ip, ipv4_dst=dst_ip)
		inst.append(parser.OFPInstructionGotoTable(200))
		msg = parser.OFPFlowMod(datapath=datapath, table_id=100, priority=3, match=match, instructions=inst) # more priority than the controller, but less than the decoy flows
		datapath.send_msg(msg)

		# actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL, 0)]
		static_flows(datapath)

	def static_flows(self, datapath, buffer_id=None):
		actions1 = [parser.OFPActionOutput(16)]
		match1 = parser.OFPMatch(eth_type = 0x0800,ipv4_src='192.168.2.2/24', ipv4_dst='192.168.3.4/24')
		# self.add_flow(datapath, 1, match, actions)
		
		actions2 = [parser.OFPActionOutput(12)]
		match2 = parser.OFPMatch(eth_type = 0x0800,ipv4_src='192.168.3.4/24', ipv4_dst='192.168.2.2/24')
		# self.add_flow(datapath, 1, match, actions)
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
								priority=priority, match=match,
								instructions=inst)
		datapath.send_msg(mod)
		

	def add_flow(self, datapath, priority, match, actions, buffer_id=None, table_id=200):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
											 actions)]
		if buffer_id:
			mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
									priority=priority, match=match,
									instructions=inst, table_id=table_id)
		else:
			mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
									match=match, instructions=inst, table_id=table_id)
		datapath.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		# If you hit this you might want to increase
		# the "miss_send_length" of your switch
		print("hello")
		if ev.msg.msg_len < ev.msg.total_len:
			self.logger.debug("packet truncated: only %s of %s bytes",
							  ev.msg.msg_len, ev.msg.total_len)
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			# ignore lldp packet
			return
		dst = eth.dst
		src = eth.src

		dpid = format(datapath.id, "d").zfill(16)
		self.mac_to_port.setdefault(dpid, {})

		self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

		# learn a mac address to avoid FLOOD next time.
		self.mac_to_port[dpid][src] = in_port

		if dst in self.mac_to_port[dpid]:
			out_port = self.mac_to_port[dpid][dst]
		else:
			out_port = ofproto.OFPP_FLOOD

		actions = [parser.OFPActionOutput(out_port)]

		# install a flow to avoid packet_in next time
		if out_port != ofproto.OFPP_FLOOD:


			# match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

				# check IP Protocol and create a match for IP
			if eth.ethertype == ether_types.ETH_TYPE_IP:
				ip = pkt.get_protocol(ipv4.ipv4)
				srcip = ip.src
				dstip = ip.dst
				match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
										ipv4_src=srcip,
										ipv4_dst=dstip
										)

			# verify if we have a valid buffer_id, if yes avoid to send both
			# flow_mod & packet_out
				if msg.buffer_id != ofproto.OFP_NO_BUFFER:
					self.add_flow(datapath, 1, match, actions, msg.buffer_id)
					return
				else:
					self.add_flow(datapath, 1, match, actions)
		data = None
		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
			data = msg.data

		out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
								  in_port=in_port, actions=actions, data=data)
		datapath.send_msg(out)
