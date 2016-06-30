#!/usr/bin/env python

from optparse import OptionParser
import socket
import sys
import json
import re

def main():

    desc = ( 'Send JSON Events' )
    usage = ( '%prog [options]\n'
              '(type %prog -h for details)' )
    op = OptionParser( description=desc, usage=usage )

    # Options
    op.add_option( '--reg', action="store", \
                     dest="register", help = "service registration information. Example: --reg='{ vnf_id=999, name=\'Yo-forwarder\', type_id=1, group_id=1, geo_location=\'server1.rack5.row17.room2\', iftype=1, bidirectional=False }'" )

    op.add_option( '--file', action="store",  \
                     dest="file", help = 'File containing the service registration information. It should follow the format of the registration as above i.e., starts with {..' )

    op.add_option( '--event-name', '-n', action="store",\
                     dest="event_name", help = 'The event name: Registration, Status, Deregistration'  )

    #op.add_option( '--event-value', '-l', action="store",\
    #                 dest="event_value", help = 'The event value.'  )

    op.add_option( '--addr', '-a', action="store",\
                     dest="addr", help = 'The address of the controller.' )

    op.add_option( '--port', '-p', action="store",\
                     dest="port", help = 'The port value of the controller.' )

    # Parsing and processing
    options, args = op.parse_args()

    register_str=None

    if options.addr is None and options.port is None:
        print 'No IP address or Port information is given. Exiting.'
        return
    elif options.event_name is None:
        print 'No event name provided. Exiting.'
        return
    #elif options.event_value is None:
    #    print 'No event value provided. Exiting.'
    #    return

    # Open file if specified
    elif options.file and options.register:
        print 'Can only specify one of (file,register)'
        return

    elif options.file:
        try:
            fd = open(options.file, 'r')
        except IOError as err:
            print 'Error opening file: ', err
            print 'Aborting.\n'
            sys.exit(1)

        content = fd.read()
        register_str = content

    elif options.register:
        register_str = options.register

    if register_str:
        # Parse register
        register_dict = dict(
            vnf_id = None,
            name=None,
            type_id=None,
            group_id=None,
            geo_location=None,
            iftype=None,
            bidirectional=None)

        parse_register_str(register_dict, register_str)

        # Construct JSON message
        json_message = dict(name=options.event_name,
                            register=register_dict)
    else:
        # Construct JSON message
        json_message = dict(name=options.event_name)

    # Create socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error:
        print 'Failed to create socket'
        sys.exit()
    # Connect to server
    #s.connect((options.addr, int(options.port)))
    #bufsize = len(json_message)

    # Send data
    totalsent = 0
    #s.sendall(json.dumps(json_message))
    s.sendto(json.dumps(json_message), (options.addr, int(options.port)) )
    # Receive return value
    #recvdata = s.recv(1024)
    #------recvdata, addr= s.recvfrom(1024)
    #----print 'return: ' + recvdata
    #recvdata,addr = s.recvfrom(1024)
    #print 'return: ' + recvdata
    #s.close()

def parse_register_str(register_dict, register_str):
    print "\nregister_Str = " + register_str
    m = re.search("name=[\'\"]?([\w._-]+)",register_str)
    if m:
        register_dict['name'] = m.group(1)

    m = re.search("vnf_id=(\d+)\s*",register_str)
    if m:
        register_dict['vnf_id'] = m.group(1)


    m = re.search("type_id=(\d+)\s*",register_str)
    if m:
        register_dict['type_id'] = m.group(1)

    m = re.search("group_id=(\d+)\s*",register_str)
    if m:
        register_dict['group_id'] = m.group(1)

    m = re.search("geo_location=[\'\"]?([\w._-]+)",register_str)
    if m:
        register_dict['geo_location'] = m.group(1)

    m = re.search("iftype=(\d+)\s*",register_str)
    if m:
        register_dict['iftype'] = m.group(1)

    m = re.search("bidirectional=[\'\"]?(\w+)",register_str)
    if m:
        register_dict['bidirectional'] = m.group(1)
                #--------------------------------------------------------------------
    print "\nData Payload = " + str(register_dict) + '\n'

# main ######
if __name__ == '__main__':
    main()

