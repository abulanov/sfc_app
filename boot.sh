#!/bin/sh
#export PATH=$PATH:/usr/share/openvswitch/scripts/ &&\
ovs-ctl start &&\
ovs-vsctl add-br lan-br &&\
ovs-vsctl add-port lan-br eth0 &&\
PORT_IP=$(ip add show dev eth0 | grep inet | awk '{print $2}') &&\
GW_IP=$(ip route | grep default | awk '{print $3}') &&\
ip addr del $PORT_IP dev eth0 &&\
ip ad add $PORT_IP dev lan-br &&\
ip link set lan-br up &&\
ip route add default via $GW_IP dev lan-br &&\
ovs-vsctl set-controller lan-br tcp:$GW_IP:6633 &&\
sleep 5 &&\
echo "Registring" &&\
/json_register.py $@


/bin/sh
