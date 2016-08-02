from mininet.topo import Topo
from mininet.link import Link
class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )
        sw1 = self.addSwitch( 's1' )
        sw2 = self.addSwitch( 's2' )
        sw3 = self.addSwitch( 's3' )
        sw4 = self.addSwitch( 's4' )
        sw5 = self.addSwitch( 's5' )

        host1 = self.addHost( 'h1' )
        host2 = self.addHost( 'h2' )
        host3 = self.addHost( 'h3' )
        host4 = self.addHost( 'h4' )
        host5 = self.addHost( 'h5' )

        self.addLink(host1, sw1)
        self.addLink(host2, sw2)

        self.addLink(host3, sw3)

        self.addLink(host4, sw4)
        self.addLink(host5, sw5)

        self.addLink(host2, sw3)
        self.addLink(host3, sw4)
        self.addLink(sw1,sw2)
        self.addLink(sw2,sw3)
        self.addLink(sw3,sw4)
        self.addLink(sw4,sw5)
#        Link(host2, sw3,  intfName1='h2-eth1')
#        host2.cmd('ip addr add 10.0.0.12/8 dev h2-eth1')
        print (host2) 
#        host2.cmd('ip route add 10.0.0.5/32 dev h2-eth1')

topos = { 'mytopo': ( lambda: MyTopo() ) }
