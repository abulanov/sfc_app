Instead of mininet, the demonstration can run on docker containers. 
![Dockerized demo environment](https://github.com/abulanov/sfc_app/blob/master/src/docker-sfc-demonstration.jpg)
1.	Build the image for the vnf container from Docker file in the current directory:
    * ```docker build -t abulanov/ovs:latest .```
2.	Start sfc application on the host:
    * ```ryu-manager --verbose ./sfc_app.py```
3.	Launch two containers or more containers to generate data flow:
    * ```docker run  -itd --rm --name src  --cap-add NET_ADMIN abulanov/ovs:latest```
    * ```docker run  -itd --rm --name dst  --cap-add NET_ADMIN abulanov/ovs:latest```
4.	Check ip addresses and create the related flow in the flow table in the database:
    * ```docker exec src ip ad```
    * ```docker exec dst ip ad``` 

    | id | ipv4_src   | ipv4_dst   | service_id |
    |----|------------|------------|------------|
    | 5  | 172.17.0.2 | 172.17.0.3 | 6          |
5.	Launch two containerized VNFs, one of which is bidirectional one:
    * ```docker run  -itd --rm --name fwd555  --cap-add NET_ADMIN abulanov/ovs:latest --reg='{name='forwarder555',vnf_id=555,type_id=1,group_id=1,iftype=3,bidirectional=False,geo_location='server555.rack2.row3.room4'}' -a 172.17.0.1  -p 30012 -n registration```
    * ```docker run  -itd --rm --name fwd777  --cap-add NET_ADMIN abulanov/ovs:latest --reg='{name='forwarder777',vnf_id=777,type_id=1,group_id=1,iftype=3,bidirectional=True,geo_location='server777.rack2.row3.room4'}' -a 172.17.0.1  -p 30012 -n registration```
6.	Check connectivity and default OpenFlow rules before SFC applied:
    * ```docker exec src traceroute -I 172.17.0.3```
    * ```docker exec dst traceroute -I 172.17.0.2```
    * ```for i in $(docker ps --format {{.Names}}); do  echo $i; docker exec $i  ovs-ofctl -O OpenFlow13 dump-flows lan-br; done```
    * Containers are seen in one hop away from each other in both directions. Default rules are installed.

7.	Apply an SFC:
    * ```curl -v http://127.0.0.1:8080/add_flow/6```
    * ```for i in $(docker ps --format {{.Names}}); do  echo $i; docker exec $i  ovs-ofctl -O OpenFlow13 dump-flows lan-br; done```
    * After the flow application catching rules for both directions are seen on the switches in the containers. Flow 5 is bound to a service with a bidirectional VNF in it.

8.	Check connectivity between the first two containers:
    * ```docker exec src traceroute -I 172.17.0.3```
    * ```docker exec dst traceroute -I 172.17.0.2```
    * ```for i in $(docker ps --format {{.Names}}); do  echo $i; docker exec $i  ovs-ofctl -O OpenFlow13 dump-flows lan-br; done```
    * Now traffic passes three hops in the forward direction and two hops in backward one.  The catching rules have been replaced with steering ones.
