        
import sqlite3
import json
import copy
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER,CONFIG_DISPATCHER,DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import udp
from ryu.lib.packet import ipv4

#sfc_instance_name = 'sfc_api_app'

conn = sqlite3.connect('nfv.sqlite')
cur = conn.cursor()


class SFCController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(SFCController, self).__init__(req, link, data, **config)
        self.sfc_api_app = data['sfc_api_app']
###### JUST FOR FUN
#    @route('hello', '/{greeting}/{name}', methods=['GET'])
#    def hello(self, req, **kwargs):
#        print kwargs
#        greeting = kwargs['greeting']
#        name = kwargs['name']
#        message = greeting +' '+ name
#        privet = {'message': message}
#        body = json.dumps(privet)
        
#        return Response(content_type='application/json', body=body)

    @route('add-flow', '/add_flow/{flow_id}', methods=['GET'])
    def api_add_flow(self,req, **kwargs):
        sfc_app = self.sfc_api_app
        
        cur.execute('''select * from flows where id = ?''',(kwargs['flow_id'],))
        flow_spec = cur.fetchone()
        if not flow_spec: return Response(status = 404)
        while flow_spec:
            (flow_id,name,in_port,eth_dst,eth_src,eth_type,ip_proto,ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,udp_dst,ipv6_src,ipv6_dst,service_id)=flow_spec
            if not eth_type: eth_type = 0x0800  
            actions = []
            for dp in sfc_app.datapaths.values():
                match_add = sfc_app.create_match(dp.ofproto_parser, [
                                               (dp.ofproto.OXM_OF_IN_PORT,in_port),
                                               (dp.ofproto.OXM_OF_ETH_SRC,eth_src),
                                               (dp.ofproto.OXM_OF_ETH_DST,eth_dst),
                                               (dp.ofproto.OXM_OF_ETH_TYPE,eth_type),
                                               (dp.ofproto.OXM_OF_IPV4_SRC,sfc_app.ipv4_to_int(ipv4_src)),
                                               (dp.ofproto.OXM_OF_IPV4_DST,sfc_app.ipv4_to_int(ipv4_dst)),
                                               (dp.ofproto.OXM_OF_IP_PROTO,ip_proto),
                                               (dp.ofproto.OXM_OF_TCP_SRC,tcp_src),
                                               (dp.ofproto.OXM_OF_TCP_DST,tcp_dst),
                                               (dp.ofproto.OXM_OF_UDP_SRC,udp_src),
                                               (dp.ofproto.OXM_OF_UDP_DST,udp_dst),
                                               (dp.ofproto.OXM_OF_IPV6_SRC,ipv6_src),
                                               (dp.ofproto.OXM_OF_IPV6_DST,ipv6_dst)
                                               ])
            
                sfc_app.add_flow(dp, 0, match_add, actions, metadata=flow_id, goto_id=2)
            
            flow_spec = cur.fetchone()
            return Response(status = 200)

    @route('delete-flow', '/delete_flow/{flow_id}', methods=['GET'])
    def api_delete_flow(self,req, **kwargs):
        sfc_app = self.sfc_api_app

        cur.execute('''select * from flows where id = ?''',(kwargs['flow_id'],))
        flow_spec = cur.fetchone()
        if not flow_spec: return Response(status = 404)
        (flow_id,name,in_port,eth_dst,eth_src,eth_type,ip_proto,ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,udp_dst,ipv6_src,ipv6_dst,service_id)=flow_spec
        if not eth_type: eth_type = 0x0800  
        for dp in sfc_app.datapaths.values():
            match_del = sfc_app.create_match(dp.ofproto_parser, [
#                                               (dp.ofproto.OXM_OF_METADATA,int(kwargs['flow_id']))
                                               (dp.ofproto.OXM_OF_IN_PORT,in_port),
                                               (dp.ofproto.OXM_OF_ETH_SRC,eth_src),
                                               (dp.ofproto.OXM_OF_ETH_DST,eth_dst),
                                               (dp.ofproto.OXM_OF_ETH_TYPE,eth_type),
                                               (dp.ofproto.OXM_OF_IPV4_SRC,sfc_app.ipv4_to_int(ipv4_src)),
                                               (dp.ofproto.OXM_OF_IPV4_DST,sfc_app.ipv4_to_int(ipv4_dst)),
                                               (dp.ofproto.OXM_OF_IP_PROTO,ip_proto),
                                               (dp.ofproto.OXM_OF_TCP_SRC,tcp_src),
                                               (dp.ofproto.OXM_OF_TCP_DST,tcp_dst),
                                               (dp.ofproto.OXM_OF_UDP_SRC,udp_src),
                                               (dp.ofproto.OXM_OF_UDP_DST,udp_dst),
                                               (dp.ofproto.OXM_OF_IPV6_SRC,ipv6_src),
                                               (dp.ofproto.OXM_OF_IPV6_DST,ipv6_dst)
                                               ])

            match = copy.copy(match_del)
            sfc_app.del_flow(datapath=dp,match=match)
        return Response(status = 200)  

class sfc_app (app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = { 'wsgi': WSGIApplication }

    def __init__(self, *args, **kwargs):
        super(sfc_app, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(SFCController, {'sfc_api_app': self})
        
        
        self.datapaths = {}
######## database definition
#        conn = sqlite3.connect('nfv.sqlite')
#        cur = conn.cursor()
#        cur.executescript('''

#        DROP TABLE IF EXISTS vnf; 

#        CREATE TABLE vnf (
#            id  INTEGER NOT NULL,
#            name    TEXT,
#            type_id  INTEGER,
#            group_id    INTEGER,
#            geo_location    TEXT,
#            iftype  INTEGER,
#            bidirectional   BOOLEAN,
#            dpid    INTEGER,
#            in_port INTEGER,
#            locator_addr  NUMERIC
#            PRIMARY KEY(id,iftype)
#        );
#        create unique index equipment_uind on vnf (name,iftype)

#        ''')
#        conn.commit()
#        cur.close()
########  END of database definition

######### Register/Unregister DataPathes in datapth dictionary
    @set_ev_cls(ofp_event.EventOFPStateChange,
            [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]


########## Setting default rules upon DP is connectted
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

################# Set flow to retrieve registration packet
        match = parser.OFPMatch(eth_type=0x0800, ip_proto = 17 , udp_dst=30012)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 1, match, actions)

########### Add catching rules to a DP upon it is connected
        cur.execute('''select * from flows''')
        flow_spec = cur.fetchone()
        while flow_spec:
            (flow_id,name,in_port,eth_dst,eth_src,eth_type,ip_proto,ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,udp_dst,ipv6_src,ipv6_dst,service_id)=flow_spec
            if not eth_type: eth_type = 0x0800  
            actions = []  
            match = self.create_match(parser, [
                                               (ofproto.OXM_OF_IN_PORT,in_port),
                                               (ofproto.OXM_OF_ETH_SRC,eth_src),
                                               (ofproto.OXM_OF_ETH_DST,eth_dst),
                                               (ofproto.OXM_OF_ETH_TYPE,eth_type),
                                               (ofproto.OXM_OF_IPV4_SRC,self.ipv4_to_int(ipv4_src)),
                                               (ofproto.OXM_OF_IPV4_DST,self.ipv4_to_int(ipv4_dst)),
                                               (ofproto.OXM_OF_IP_PROTO,ip_proto),
                                               (ofproto.OXM_OF_TCP_SRC,tcp_src),
                                               (ofproto.OXM_OF_TCP_DST,tcp_dst),
                                               (ofproto.OXM_OF_UDP_SRC,udp_src),
                                               (ofproto.OXM_OF_UDP_DST,udp_dst),
                                               (ofproto.OXM_OF_IPV6_SRC,ipv6_src),
                                               (ofproto.OXM_OF_IPV6_DST,ipv6_dst)
                                               ])
            self.add_flow(datapath, 0, match, actions, metadata=flow_id, goto_id=2)
            
            flow_spec = cur.fetchone()
        
############### Default actions to tables 0, 1, 2
        actions = []
        match = parser.OFPMatch()
        self.add_flow(datapath, 0, match, actions,goto_id=1)
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL,
           ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions,table_id=1)

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
           ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions,table_id=2)
################ Packet_IN handler ####################
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        actions = []
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto 
        parser = datapath.ofproto_parser 

        if msg.reason == ofproto.OFPR_NO_MATCH:
            reason = 'NO MATCH'
        elif msg.reason == ofproto.OFPR_ACTION:
            reason = 'ACTION'
        elif msg.reason == ofproto.OFPR_INVALID_TTL:
            reason = 'INVALID TTL'
        else:
            reason = 'unknown'
        self.logger.debug('OFPPacketIn received: '
                          'buffer_id=%x total_len=%d reason=%s '
                          'table_id=%d cookie=%d  match=%s ',
                           msg.buffer_id, msg.total_len, reason,
                           msg.table_id,  msg.cookie, msg.match )
        try:
            flow_match = msg.match['metadata']
            in_port_entry = msg.match['in_port']
            dp_entry_point = datapath


            cur.execute('''select * from flows where id = ? ''',(flow_match,))
            flow_spec = cur.fetchone()
            (flow_id,name,in_port,eth_dst,eth_src,eth_type,ip_proto,ipv4_src,ipv4_dst,tcp_src,tcp_dst,udp_src,udp_dst,ipv6_src,ipv6_dst,service_id)=flow_spec
            if not eth_type: eth_type = 0x0800  
            actions_entry_point = []  
            match_entry_point = self.create_match(parser, [
                                               (ofproto.OXM_OF_IN_PORT,in_port_entry),
                                               (ofproto.OXM_OF_ETH_SRC,eth_src),
                                               (ofproto.OXM_OF_ETH_DST,eth_dst),
                                               (ofproto.OXM_OF_ETH_TYPE,eth_type),
                                               (ofproto.OXM_OF_IPV4_SRC,self.ipv4_to_int(ipv4_src)),
                                               (ofproto.OXM_OF_IPV4_DST,self.ipv4_to_int(ipv4_dst)),
                                               (ofproto.OXM_OF_IP_PROTO,ip_proto),
                                               (ofproto.OXM_OF_TCP_SRC,tcp_src),
                                               (ofproto.OXM_OF_TCP_DST,tcp_dst),
                                               (ofproto.OXM_OF_UDP_SRC,udp_src),
                                               (ofproto.OXM_OF_UDP_DST,udp_dst),
                                               (ofproto.OXM_OF_IPV6_SRC,ipv6_src),
                                               (ofproto.OXM_OF_IPV6_DST,ipv6_dst)
                                               ])

            
            match_common = self.create_match(parser, [
                                               (ofproto.OXM_OF_IN_PORT,in_port),
                                               (ofproto.OXM_OF_ETH_SRC,eth_src),
                                               (ofproto.OXM_OF_ETH_DST,eth_dst),
                                               (ofproto.OXM_OF_ETH_TYPE,eth_type),
                                               (ofproto.OXM_OF_IPV4_SRC,self.ipv4_to_int(ipv4_src)),
                                               (ofproto.OXM_OF_IPV4_DST,self.ipv4_to_int(ipv4_dst)),
                                               (ofproto.OXM_OF_IP_PROTO,ip_proto),
                                               (ofproto.OXM_OF_TCP_SRC,tcp_src),
                                               (ofproto.OXM_OF_TCP_DST,tcp_dst),
                                               (ofproto.OXM_OF_UDP_SRC,udp_src),
                                               (ofproto.OXM_OF_UDP_DST,udp_dst),
                                               (ofproto.OXM_OF_IPV6_SRC,ipv6_src),
                                               (ofproto.OXM_OF_IPV6_DST,ipv6_dst)
                                               ])
            #### DELETE PREINSTALLED CATCHING FLOWS
            for dp in self.datapaths.values():

                match = copy.copy(match_common)
                self.del_flow(datapath=dp,match=match)
            
            # Iterrgoate DB on VNFS
            cur.execute('''select vnf_id from service where service_id = ? and  prev_vnf_id is NULL  ''',(service_id,))
            vnf_id = cur.fetchone()[0]
            ### added iftype bitwise support: 1(01)-out, 2(10)-in, 3(11)-inout
            cur.execute(''' select locator_addr from vnf where id=? and iftype & 2 != 0''',(vnf_id,))
            # Ex. bitwise iftype selection 'select * from vnf where  iftype & 2 != 0'
            # & 1 - first bit; & 2 - second bit
            #select dpid, in_port, locator_addr from vnf where id=7 and iftype & 2 != 0
            locator_addr = cur.fetchone()[0]

            cur.execute(''' select dpid, in_port from vnf where id=? and iftype & 1 != 0''',(vnf_id,))

            dpid, in_port = cur.fetchone()

            actions_entry_point.append(parser.OFPActionSetField(eth_dst=locator_addr))
            self.add_flow(dp_entry_point, 8, match_entry_point, actions_entry_point, goto_id=1)
            while True:
                datapath = self.datapaths[dpid]
                actions = []
                match = self.create_match(parser, [
                                               (ofproto.OXM_OF_IN_PORT,in_port),
                                               (ofproto.OXM_OF_ETH_SRC,eth_src),
                                               (ofproto.OXM_OF_ETH_DST,eth_dst),
                                               (ofproto.OXM_OF_ETH_TYPE,eth_type),
                                               (ofproto.OXM_OF_IPV4_SRC,self.ipv4_to_int(ipv4_src)),
                                               (ofproto.OXM_OF_IPV4_DST,self.ipv4_to_int(ipv4_dst)),
                                               (ofproto.OXM_OF_IP_PROTO,ip_proto),
                                               (ofproto.OXM_OF_TCP_SRC,tcp_src),
                                               (ofproto.OXM_OF_TCP_DST,tcp_dst),
                                               (ofproto.OXM_OF_UDP_SRC,udp_src),
                                               (ofproto.OXM_OF_UDP_DST,udp_dst),
                                               (ofproto.OXM_OF_IPV6_SRC,ipv6_src),
                                               (ofproto.OXM_OF_IPV6_DST,ipv6_dst)
                                               ])
                cur.execute('''select next_vnf_id from service where service_id = ? and vnf_id = ?  ''',(service_id,vnf_id))
                next_vnf_id = cur.fetchone()[0]
                if next_vnf_id:
                    ### added iftype support
                    cur.execute(''' select locator_addr from vnf where id=? and iftype & 2 != 0''',(next_vnf_id,))
                    locator_addr = cur.fetchone()[0]
                    cur.execute(''' select dpid, in_port from vnf where id=? and iftype & 1 != 0''',(next_vnf_id,))
                    dpid, in_port = cur.fetchone()

                    actions.append(parser.OFPActionSetField(eth_dst=locator_addr))
                    self.add_flow(datapath, 8, match,  actions,goto_id=1)
                    vnf_id = next_vnf_id
                else:
                    actions = [] 
                    self.add_flow(datapath, 8, match, actions,goto_id=1)
                    break
                ### added iftype support
               # cur.execute(''' select dpid, in_port, locator_addr from vnf where id=? and iftype & 1 != 0''',(vnf_id,))
               # dpid, in_port, locator_addr = cur.fetchone()

                cur.execute(''' select locator_addr from vnf where id=? and iftype & 2 != 0''',(next_vnf_id,))
                locator_addr = cur.fetchone()[0]
                cur.execute(''' select dpid, in_port from vnf where id=? and iftype & 1 != 0''',(next_vnf_id,))
                dpid, in_port = cur.fetchone()

        except KeyError:
            flow_match = None
            pass


#----------------------------------

####### VNF self registrtation


        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        pkt_arp = pkt.get_protocol(arp.arp) 
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        pkt_ip = pkt.get_protocol(ipv4.ipv4)
 

        pkt_udp = pkt.get_protocol(udp.udp)
        if pkt_udp:
            if pkt_udp.dst_port == 30012:
                ######
                #Deebug
                ######
                print "Packet_IN 30012 has arrived"
                reg_string=pkt.protocols[-1]
                reg_info = json.loads(reg_string)
                name=reg_info['register']['name']
                id=reg_info['register']['vnf_id']
                type_id=reg_info['register']['type_id']
                group_id=reg_info['register']['group_id']
                geo_location=reg_info['register']['geo_location']
                iftype=reg_info['register']['iftype']
                bidirectional=reg_info['register']['bidirectional']
                dpid=datapath.id
                locator_addr=pkt_eth.src

                cur.execute('''INSERT OR IGNORE INTO vnf (id, name, type_id,
                        group_id, geo_location, iftype, bidirectional,
                        dpid, in_port, locator_addr  ) VALUES ( ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ? )''', ( id, name, type_id,
                            group_id, geo_location, iftype,
                            bidirectional, dpid, in_port, locator_addr )
                        )
                cur.execute('SELECT id FROM vnf WHERE name = ? AND  iftype = ?',
                        (name, iftype))
                vnf_id = cur.fetchone()[0]

                conn.commit()
                #cur.close()


                
############# Function definitions #############


    def add_flow(self, datapath, priority, match, actions,
            buffer_id=None, table_id=0,metadata=None,goto_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        

        if goto_id:
            #inst = [parser.OFPInstructionActions(ofproto.OFPIT_WRITE_ACTIONS, actions)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] # works, BUT...

            if metadata:
                inst.append(parser.OFPInstructionWriteMetadata(metadata,0xffffffff))
            inst.append(parser.OFPInstructionGotoTable(goto_id))
        else:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            #inst.append(parser.OFPInstructionWriteMetadata(1,0xffffffff))

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst,table_id=table_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    table_id=table_id)
        datapath.send_msg(mod)
#############################################

    def del_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath,
                    command=ofproto.OFPFC_DELETE,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    match=match)
        datapath.send_msg(mod)

############################################
    def create_match(self, parser, fields):
        """Create OFP match struct from the list of fields."""
        match = parser.OFPMatch()
        for a in fields:
            if  a[1]:
                match.append_field(*a)
        return match

###########################################
    def ipv4_to_int(self, string):
        ip = string.split('.')
        assert len(ip) == 4
        i = 0
        for b in ip:
            b = int(b)
            i = (i << 8) | b
        return i

###########################################
