#!/bin/sh
ovs-ctl --ovsdb-server-priority=0 --ovs-vswitchd-priority=0 start &&\
ovs-vsctl add-br lan-br &&\
ovs-vsctl add-port lan-br eth0 &&\
PORT_IP=$(ip add show dev eth0 | grep inet | awk '{print $2}') &&\
GW_IP=$(ip route | grep default | awk '{print $3}') &&\
ip addr del $PORT_IP dev eth0 &&\
ip ad add $PORT_IP dev lan-br &&\
ip link set lan-br up &&\
ip route add default via $GW_IP dev lan-br &&\
ovs-vsctl set-controller lan-br tcp:$GW_IP:6633 &&\
echo "Registering" &&\
/json_register.py $@

/bin/sh
