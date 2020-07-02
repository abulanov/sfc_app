import sqlite3
import json
import logging
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
from asymlist import Node, AsymLList, TransitionBackError

conn = sqlite3.connect('nfv.sqlite')
cur = conn.cursor()
flows={}
##################
class vnf(Node):
    def __init__(self,vnf_id,is_bidirect=True,cur=None):
        super().__init__(vnf_id ,is_bidirect)
            
        ### added iftype bitwise support: 1(01)-out, 2(10)-in, 3(11)-inout
        ### & 1 - first bit; & 2 - second bit
        ### Ex. bitwise iftype selection 'select * from vnf where  iftype & 2 != 0'
        ###                               'select dpid, in_port, locator_addr from vnf where id=X and iftype & 1 != 0'
        cur.execute(''' select dpid, in_port, locator_addr, bidirectional from vnf where id=? and iftype & 2 != 0''',(self.id,)) 
        self.dpid_in, self.port_in, self.locator_addr_in, is_bidirect = cur.fetchone()
        logging.debug('Locator addr: %s',self.locator_addr_in)
        cur.execute(''' select dpid, in_port, locator_addr from vnf where id=? and iftype & 1 != 0''',(self.id,))
        self.dpid_out, self.port_out, self.locator_addr_out = cur.fetchone()
        if is_bidirect.lower()=="false":
            self.is_bidirect = False   

class sfc(AsymLList):
    def __init__(self,flow_id,nodeClass=vnf,cur=None):
        self.cur=cur
        self.cur.execute('''select * from flows where id = ? ''',(flow_id,))
        self.flow_spec = cur.fetchone()
        if self.flow_spec is None:
            logging.debug('Flow %s is not defined', flow_id)
            raise ValueError("Flow is not known")
        self.flow_dict = {}
        self.flows = {}
        (self.flow_id,self.name,self.flow_dict['in_port'],self.flow_dict['eth_dst'],self.flow_dict['eth_src'],self.flow_dict['eth_type'],self.flow_dict['ip_proto'],self.flow_dict['ipv4_src'],self.flow_dict['ipv4_dst'],self.flow_dict['tcp_src'],self.flow_dict['tcp_dst'],self.flow_dict['udp_src'],self.flow_dict['udp_dst'],self.flow_dict['ipv6_src'],self.flow_dict['ipv6_dst'],self.service_id)=self.flow_spec
        if not self.flow_dict['eth_type']:
            self.flow_dict['eth_type'] = 0x0800

        self.flow_id = int(flow_id)
        self.reverse_flow_id = self.flow_id+3000
        self.flows[self.flow_id] = self.flow_dict
        self.flows[self.reverse_flow_id] = sfc_app_cls.reverse_flow(self.flows[self.flow_id])
        self.cur.execute('''select vnf_id from service where service_id = ? and  prev_vnf_id is NULL  ''',(self.service_id,))
        vnf_id = self.cur.fetchone()[0]
        super().__init__(vnf_id,is_bidirect=True,nodeClass=nodeClass,cur=self.cur)   
        self.fill()

    def __str__(self):
        return str(self.forward())

    def append(self):
        self.cur.execute('''select next_vnf_id from service where service_id = ? and vnf_id = ?  ''',(self.service_id,self.last.id))
        next_vnf_id = self.cur.fetchone()[0]
        if next_vnf_id is None:
            return None
        logging.debug('Trying to append %s', next_vnf_id)
        return super().append(next_vnf_id,cur=self.cur)
            
    def fill(self):
        logging.debug('Filling...')
        while self.append():
            pass
        return self.last        
    
    def install_catching_rule(self,sfc_app_cls):
        logging.debug("Adding catching rule...")    
        actions = []
        flow_id = self.flow_id
        for flow_id in (self.flow_id, self.reverse_flow_id):
            for dp in sfc_app_cls.datapaths.values():
                match = sfc_app_cls.create_match(dp.ofproto_parser,self.flows[flow_id])
                sfc_app_cls.add_flow(dp, 1, match, actions, metadata=flow_id, goto_id=2)
            if self.back is None:
                break
        return Response(status = 200)

    def delete_rule(self,sfc_app_cls,flow_match):
        logging.debug('Deleting rule...')
        flow_dict = self.flows[flow_match]
        for dp in sfc_app_cls.datapaths.values():
            match_del = sfc_app_cls.create_match(dp.ofproto_parser,flow_dict)
            sfc_app_cls.del_flow(datapath=dp,match=match_del)

    def install_steering_rule(self, sfc_app_cls, dp_entry, in_port_entry, flow_match):
        logging.debug("Adding steering rule...")
        actions = []
        dp=dp_entry
        parser=dp.ofproto_parser
        flow_dict=self.flows[flow_match]
        flow_dict['in_port']=in_port_entry
        match = sfc_app_cls.create_match(parser,flow_dict)
        if flow_match < 3000:
            for vnf in self.forward():
                dpid_out=vnf.dpid_out
                actions.append(parser.OFPActionSetField(eth_dst=vnf.locator_addr_in)) 
                sfc_app_cls.add_flow(dp, 8, match, actions, goto_id=1)
                actions = []
                flow_dict['in_port']=vnf.port_out
                dp=sfc_app_cls.datapaths[vnf.dpid_out] 
                match = sfc_app_cls.create_match(parser,flow_dict)
        else:
            for vnf in self.backward(): 
                dpid_out=vnf.dpid_out
                actions.append(parser.OFPActionSetField(eth_dst=vnf.locator_addr_out)) 
                sfc_app_cls.add_flow(dp, 8, match, actions, goto_id=1)
                actions = []
                flow_dict['in_port']=vnf.port_out
                dp=sfc_app_cls.datapaths[vnf.dpid_out] 
                match = sfc_app_cls.create_match(parser,flow_dict)

#################################

class SFCController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(SFCController, self).__init__(req, link, data, **config)
        self.sfc_api_app = data['sfc_api_app']

    @route('hello', '/{greeting}/{name}', methods=['GET'])
    def hello(self, req, **kwargs):
        greeting = kwargs['greeting']
        name = kwargs['name']
        message = greeting +' '+ name
        privet = {'message': message}
        body = json.dumps(privet)
        return Response(content_type='application/json', body=body.encode('utf-8'), status = 200)

    @route('add-flow', '/add_flow/{flow_id}', methods=['GET'])
    def api_add_flow(self,req, **kwargs):
        sfc_ap = self.sfc_api_app
        flow_id=kwargs['flow_id']
        logging.debug('FLOW ID: %s',flow_id)
        try:
            flows[flow_id]=sfc(flow_id,cur=cur)
        except ValueError:
            message = {'Result': 'Flow {} is not defined'.format(flow_id)}
            body = json.dumps(message)
            return Response(content_type='application/json', body=body.encode('utf-8'), status = 404)
        except TypeError:
            message = {'Result': 'DB inconsistency'}
            body = json.dumps(message)
            return Response(content_type='application/json', body=body.encode('utf-8'), status = 500  )
        logging.debug('SFC: %s',str(flows[flow_id]))
        flows[flow_id].install_catching_rule(sfc_ap)

    @route('delete-flow', '/delete_flow/{flow_id}', methods=['GET'])
    def api_delete_flow(self,req, **kwargs):
        '''Deletes flow from the application and clears the corresponding rule from DPs  '''
        sfc_ap = self.sfc_api_app
        flow_id=kwargs['flow_id']
        cur.execute('''select * from flows where id = ?''',(kwargs['flow_id'],))
        flow_spec = cur.fetchone()
        flow_dict={}
        if not flow_spec: return Response(status = 404)

        (flow_id,name,flow_dict['in_port'],flow_dict['eth_dst'],flow_dict['eth_src'],flow_dict['eth_type'],flow_dict['ip_proto'],flow_dict['ipv4_src'],flow_dict['ipv4_dst'],flow_dict['tcp_src'],flow_dict['tcp_dst'],flow_dict['udp_src'],flow_dict['udp_dst'],flow_dict['ipv6_src'],flow_dict['ipv6_dst'],service_id)=flow_spec
        if not flow_dict['eth_type']: flow_dict['eth_type'] = 0x0800 
        reverse_flow_dict = sfc_app_cls.reverse_flow(flow_dict) 
        for flow_dict in (flow_dict, reverse_flow_dict):

            for dp in sfc_ap.datapaths.values():
                match_del = sfc_ap.create_match(dp.ofproto_parser,flow_dict)
                sfc_ap.del_flow(datapath=dp,match=match_del)
        try:    
            del flows[str(flow_id)]
            logging.debug('Flow %s deleted', flow_id)
        except KeyError:
            logging.debug('Flow %s not found, but an attempt to delete it from DPs has been performed', flow_id)
            pass
        return Response(status = 200)

    @route('flows', '/flows/{flow_id}', methods=['GET'])
    def api_show_flow(self,req, **kwargs):
        flow_id=kwargs['flow_id']
        try:
            body=json.dumps({flow_id:str(flows[flow_id])})
            return Response(content_type='application/json', body=body.encode('utf-8'), status = 200)
        except KeyError:
            body=json.dumps({'ERROR':'Flow {} not found/not installed'.format(flow_id)})
            return Response(content_type='application/json', body=body.encode('utf-8'), status = 404)

    @route('flows_all', '/flows', methods=['GET'])
    def api_show_flows(self,req, **kwargs):
        logging.debug('FLOWS: {}'.format(str(flows)))
        body=json.dumps(str(flows))
        return Response(content_type='application/json', body=body.encode('utf-8'), status = 200)

class sfc_app_cls (app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = { 'wsgi': WSGIApplication }

    def __init__(self, *args, **kwargs):
        super(sfc_app_cls, self).__init__(*args, **kwargs)
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

#### Set flow to retrieve registration packet
        match = parser.OFPMatch(eth_type=0x0800, ip_proto = 17 , udp_dst=30012)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 1, match, actions)
#### Set defaults for table 1 and 2        
        match = parser.OFPMatch()
        actions = []
        self.add_flow(datapath, 0, match, actions,goto_id=1)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL,
           ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions,table_id=1)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
           ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions,table_id=2)
################ Packet_IN handler ####################
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto 
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
            if msg.match['metadata'] > 3000:
                flow_id = flow_match - 3000
            else:
                flow_id = flow_match
            in_port_entry = msg.match['in_port']
            dp_entry = datapath

####### Deleting catching rules
            logging.debug('Deleting catching rules - flow:%d match:%d ...', flow_id, flow_match)
            flows[str(flow_id)].delete_rule(self, flow_match)

####### Installing steering rules 
            logging.debug('Installing steering rules - flow:%d match:%d ...', flow_id, flow_match)
            flows[str(flow_id)].install_steering_rule(self,dp_entry,in_port_entry,flow_match)
            
        except KeyError:
            flow_match = None
            pass

####### VNF self registrtation
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        pkt_arp = pkt.get_protocol(arp.arp) 
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        pkt_ip = pkt.get_protocol(ipv4.ipv4)
        pkt_udp = pkt.get_protocol(udp.udp)
        if pkt_udp:
            if pkt_udp.dst_port == 30012:
                reg_string=pkt.protocols[-1]
                reg_info = json.loads(reg_string)
                name=reg_info['register']['name']
                vnf_id=reg_info['register']['vnf_id']
                logging.debug('VNF ID from reg packet %s', vnf_id)
                type_id=reg_info['register']['type_id']
                group_id=reg_info['register']['group_id']
                geo_location=reg_info['register']['geo_location']
                iftype=reg_info['register']['iftype']
                bidirectional=reg_info['register']['bidirectional']
                dpid=datapath.id
                locator_addr=pkt_eth.src
                logging.debug("Inserting self-registartion info into DB")
                cur.execute('''REPLACE INTO vnf (id, name, type_id,
                        group_id, geo_location, iftype, bidirectional,
                        dpid, in_port, locator_addr  ) VALUES ( ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ? )''', ( vnf_id, name, type_id,
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
        logging.debug("Add flow to DP %d", datapath.id) 
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if goto_id:
            #inst = [parser.OFPInstructionActions(ofproto.OFPIT_WRITE_ACTIONS, actions)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] 

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

    def del_flow(self, datapath, match):
        ''' Deletes a flow defined by match from a DP '''
        logging.debug("Delele flow from DP %d", datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath,
                    command=ofproto.OFPFC_DELETE,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    match=match)
        datapath.send_msg(mod)

    def create_match(self, parser, fields):
        '''Creates OFP match struct from the list of fields. New API.'''
        flow_dict={}
        for k,v in fields.items():
            if  v is not None:
                flow_dict[k]=v
        match = parser.OFPMatch(**flow_dict)
        return match

    def reverse_flow(flow_dict):
        '''Creates reverse flow dict '''
        reverse_flow_dict = { **flow_dict}
        reverse_flow_dict['eth_src']=flow_dict['eth_dst']
        reverse_flow_dict['eth_dst']=flow_dict['eth_src']
        reverse_flow_dict['ipv4_src']=flow_dict['ipv4_dst']
        reverse_flow_dict['ipv4_dst']=flow_dict['ipv4_src']
        reverse_flow_dict['tcp_src']=flow_dict['tcp_dst']
        reverse_flow_dict['tcp_dst']=flow_dict['tcp_src']
        reverse_flow_dict['udp_src']=flow_dict['udp_dst']
        reverse_flow_dict['udp_dst']=flow_dict['udp_src']
        reverse_flow_dict['ipv6_src']=flow_dict['ipv6_dst']
        reverse_flow_dict['ipv6_dst']=flow_dict['ipv6_src']
        return reverse_flow_dict

