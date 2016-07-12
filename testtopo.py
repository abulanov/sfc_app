from mininet.topo import Topo

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


topos = { 'mytopo': ( lambda: MyTopo() ) }
