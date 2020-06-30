FROM alpine
WORKDIR /



RUN apk add --no-cache openvswitch &&\
apk add --no-cache python3 


ADD boot.sh / 
ADD json_register.py /

ENV PATH="/usr/share/openvswitch/scripts/:${PATH}" 

#RUN ovs-ctl start &&\
#ovs-vsctl add-br lan-br &&\
#ovs-vsctl add-port lan-br eth0 
ENTRYPOINT ["/boot.sh" ]





