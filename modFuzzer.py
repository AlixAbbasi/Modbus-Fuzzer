#!/usr/bin/python
'''
Created on Apr 16, 2013 v0.1

Modified and added scanning function, Dec 14, 2013 v0.2

@author: Ali, Sami
'''
import socket
import sys
from types import *
import struct

HOST = '127.0.0.1'    # The remote host
dest_port = 502            # The same port as used by the server
TANGO_DOWN = ''
sock = None
dumbflagset = 0;

def create_connection(dest_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error, msg:
        sys.stderr.write("[ERROR] %s\n" % msg[1])
        sys.exit(1)

    HOST = dest_ip
    print 'Connecting to %s' % HOST
    try:
        sock.settimeout(0.001)
        sock.connect((HOST, dest_port))
        #sock.settimeout(None)
    except socket.error, msg:
        #sys.stderr.write("[ERROR] %s\n" % msg[1])
        sys.exit(2)

    print 'Connected successfully'
    return sock

def dumb_fuzzing(dest_ip):
  sock = create_connection(dest_ip, dest_port)
  length1 = 0
  length2 = 6
  unitID = 1
  for transID1 in range(0,255):
    for transID2 in range(0,255):
      for protoID1 in range(0,255):
        for protoID2 in range(0,255):
#         for length1 in range(0,255):
#           for length2 in range(0,255):
#             for unitID in range(0,255):
                for functionCode in range(0,255):
                  for functionData1 in range(0,65535):
                    for functionData2 in range(0,65535):
                      TotalModbusPacket = struct.pack(">B", transID1) + \
                                          struct.pack(">B", transID2) + \
                                          struct.pack(">B", protoID1) + \
                                          struct.pack(">B", protoID2) + \
                                          struct.pack(">B", length1) + \
                                          struct.pack(">B", length2) + \
                                          struct.pack(">B", unitID) + \
                                          struct.pack(">B", functionCode) + \
                                          struct.pack(">H", functionData1) + \
                                          struct.pack(">H", functionData2)
#                     print '         transID  protoID  length  uID  funcCode  funcData'
                      print 'Sent Msg : %02x %02x,  %02x %02x,  %02x %02x,   %02x,   %02x,    %04x, %04x' % (transID1, transID2, protoID1, protoID2, length1, length2, unitID, functionCode, functionData1, functionData2)
                      try:
                        sock.send(TotalModbusPacket)
                      except socket.timeout:
                        print ''
                      try:
                        data = sock.recv(1024)
                        print 'Received %s:' % repr(data)
                      except socket.timeout:
                        print ''
  sock.close()

def smart_fuzzing(dest_ip, msg):
    sock = create_connection(dest_ip, dest_port)
    strInput = msg
    dataSend = ""
    shortInput = ""
    sock.send(msg)
#    cnt = 1
#    for chInput in strInput:
#    	shortInput += chInput
#        if cnt%2 == 0:
#           intInput = int(shortInput,16)
#           dataSend += struct.pack(">B", intInput)
#           print 'short: %s, intInput: %s, dataSend: %s'%(repr(shortInput), intInput, repr(dataSend))
#           shortInput = ""
#        cnt += 1
#    print '%s' % repr(dataSend)
#    sock.send(dataSend)
#    print 'sent: %s' % repr(dataSend)
    print '%s' % repr(msg)
    try:
        dataRecv = sock.recv(1024)
        print >>sys.stderr, 'received: %s' % repr(dataRecv)
    except socket.timeout:
        print 'recv timed out'
#    if dataRecv==TANGO_DOWN:
#        print 'TANGO DOWN !!!'
    sock.close()


def atod(a): # ascii_to_decimal
    return struct.unpack("!L",socket.inet_aton(a))[0]

def dtoa(d): # decimal_to_ascii
    return socket.inet_ntoa(struct.pack("!L", d))


def scan_device(ip_range):
    net,_,mask = ip_range.partition('/')
    mask = int(mask)
    net = atod(net)
    for dest_ip in (dtoa(net+n) for n in range(0, 1<<32-mask)):
        try:
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        except socket.error, msg:
            sock.close()

        try:
            sock.settimeout(0.2);
            sock.connect((dest_ip, dest_port))
        except socket.error, msg:
            print "connection error at %s" % dest_ip
            continue
        except socket.timeout:
            print 'ip %s timeout error' % dest_ip
            continue

        unitID = 0
        dataRecv = '' 
        while True:
            dataSend =  struct.pack(">H", 0) \
                            + struct.pack(">H", 0) \
                            + struct.pack(">H", 6) \
                            + struct.pack(">B", unitID) \
                            + struct.pack(">B", 3) \
                            + struct.pack(">H", 0) \
                            + struct.pack(">H", 1)
            try:
                sock.send(dataSend)
                print "Sent: %s to %s" % (repr(dataSend), dest_ip)
            except socket.error:
                print 'FAILED TO SEND'
                #sock.close()
                #continue

            try:
                dataRecv = sock.recv(1024)
                print "Recv : %s" % repr(dataRecv)
            except socket.timeout:
                sys.stdout.write('.')

            if len(dataRecv) < 1:
                sys.stdout.write('.')
                #print "."
                unitID += 1
            else:
                print '\nunit ID %d found at IP %s' % (unitID, dest_ip)
                if dumbflagset == 1 :
                    print 'now starting dumb fuzzing'
                    dumb_fuzzing(dest_ip)
                break
    sock.close()


# main starts here

if len(sys.argv) < 3:
    print "modbus fuzzer v0.1"
    print ""
    print "Usage: python modFuzzer.py [-D] [destination_IP]"
    print "                           [-I] [destination_IP] [packet]"
    print "                           [-S] [IP_range]"
    print "                           [-SD][IP_range]"
    print " "
    print "Commands:"
    print "Either long or short options are allowed."
    print "  --dumb    -D  Fuzzing in dumb way"
    print "  --input   -I  Fuzzing with given modbus packet"
    print "  --scan    -S  Scan the modbus device(s) in given IP range"
    print "  --sc_dumb -SD Scan the device(s) and doing dumb fuzzing"
#    print " "
#    print "Option:"
#    print "  --port    -p  Port number"
    print " "
    print "Example:"
    print "python modFuzzer.py -D 192.168.0.123"
#    print "python modFuzzer.py -D 192.168.0.123 -p 8888"
    print "python modFuzzer.py -I 192.168.0.23 0000000000060103000A0001"
    print "python modFuzzer.py -S 192.168.0.0/24"
    print ""
    exit(1)

argv1 = sys.argv[1]
argv2 = sys.argv[2]
argv3 = ''
if len(sys.argv) > 3:
    argv3 = sys.argv[3]

if (argv1=='-D') or (argv1=='--dumb'):	# dumb fuzzing
    dumb_fuzzing(argv2)
    sys.exit(1)

elif (argv1=='-I') or (argv1=='--input'):	# smart user input
    smart_fuzzing(argv2, argv3)

elif (argv1=='-S') or (argv1=='--scan') or (argv1=='-SD'):       # scan device
    if argv1 =='-SD' :
        dumbflagset = 1 
    scan_device(argv2)


sys.exit(0)
