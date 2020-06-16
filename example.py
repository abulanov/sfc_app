#!/usr/bin/python2
 
"""
"""
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch,UserSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import Link, TCLink
 
def topology():
    """Create a network"""
    net = Mininet( controller=RemoteController, link=TCLink, switch=OVSKernelSwitch )
 
    print("*** Creating nodes")
    h1 = net.addHost( 'h1', mac='00:00:00:00:00:01', ip='10.0.0.1/24' )
    h2 = net.addHost( 'h2', mac='00:00:00:00:00:02', ip='10.0.0.2/24' )
    h3 = net.addHost( 'h3', mac='00:00:00:00:00:03', ip='10.0.0.3/24' )
    h4 = net.addHost( 'h4', mac='00:00:00:00:00:04', ip='10.0.0.4/24' )
    h5 = net.addHost( 'h5', mac='00:00:00:00:00:05', ip='10.0.0.5/24' )
    s1 = net.addSwitch( 's1', listenPort=6671 )
    s2 = net.addSwitch( 's2', listenPort=6672 )
    s3 = net.addSwitch( 's3', listenPort=6673 )
    s4 = net.addSwitch( 's4', listenPort=6674 )
    s5 = net.addSwitch( 's5', listenPort=6675 )
    c7 = net.addController( 'c7', controller=RemoteController, ip='127.0.0.1', port=6633 )
 
    print("*** Creating links")
    
    net.addLink(s1, h1)
    net.addLink(s2, h2)
    net.addLink(s3, h3)
    net.addLink(s4, h4)
    net.addLink(s5, h5)
    net.addLink(s1, s2)
    net.addLink(s2, s3)
    net.addLink(s3, s4)
    net.addLink(s4, s5)
    net.addLink(s3, h2)
    net.addLink(s4, h3)
    h2.cmd('ifconfig h2-eth1 10.0.0.12 netmask 255.255.255.0')
    h3.cmd('ifconfig h3-eth1 10.0.0.13 netmask 255.255.255.0')

    print ("*** Starting network")

    net.build()
    h2.cmd('ip route add 10.0.0.1/32 dev h2-eth0; ip route add 10.0.0.5/32 dev h2-eth1')
    h2.cmd('ip route add 10.0.0.253/32 dev h2-eth0; ip route add 10.0.0.254/32 dev h2-eth1')
    h2.cmd('sudo arp -i h2-eth0 -s 10.0.0.253 01:02:03:04:05:06')
    h2.cmd('sudo arp -i h2-eth1 -s 10.0.0.254 11:12:13:14:15:16')
    
    h3.cmd('ip route add 10.0.0.1/32 dev h3-eth0; ip route add 10.0.0.5/32 dev h3-eth1')
    h3.cmd('ip route add 10.0.0.253/32 dev h3-eth0; ip route add 10.0.0.254/32 dev h3-eth1')
    h3.cmd('sudo arp -i h3-eth0 -s 10.0.0.253 01:02:03:04:05:06')
    h3.cmd('sudo arp -i h3-eth1 -s 10.0.0.254 11:12:13:14:15:16')

    h5.cmd('sudo arp -i h5-eth0 -s 10.0.0.253 01:02:03:04:05:06')

    c7.start()
    s1.start( [c7] )
    s2.start( [c7] )
    s3.start( [c7] )
    s4.start( [c7] )
    s5.start( [c7] )

    h2.cmd('./json_register.py --file=forwarder1.txt -a 10.0.0.253 -p 30012 -n registration')
    h2.cmd('./json_register.py --file=forwarder1-2.txt -a 10.0.0.254 -p 30012 -n registration')
    h3.cmd('./json_register.py --file=forwarder2-1.txt -a 10.0.0.253 -p 30012 -n registration')
    h3.cmd('./json_register.py --file=forwarder2-2.txt -a 10.0.0.254 -p 30012 -n registration')
    h5.cmd('./json_register.py --file=forwarder3.txt -a 10.0.0.253 -p 30012 -n registration')
    print("*** Running CLI")
    CLI( net )
 
    print("*** Stopping network")
    net.stop()
 
if __name__ == '__main__':
    setLogLevel( 'info' )
    topology()
