#!/usr/bin/python
'''
Created on Apr 16, 2013 v0.1
Modified and added scanning function, Dec 14, 2013 v0.2
Added fuzzing feature for specific function code, Apr 30, 2014 v0.5

@author: Ali, TJ
'''
import socket
import sys
from types import *
import struct
import time
import logging

HOST = '127.0.0.1'    # The remote host
dest_port = 502       # The same port as used by the server
TANGO_DOWN = ''
sock = None
dumbflagset = 0;
logging.basicConfig(filename='./fuzzer.log', filemode='a', level=logging.DEBUG, format='[%(asctime)s][%(levelname)s] %(message)s')

def create_connection(dest_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error, msg:
        sys.stderr.write("[ERROR] %s\n" % msg[1])
        sys.exit(1)

    HOST = dest_ip
    try:
        sock.settimeout(0.5)
        sock.connect((HOST, dest_port))
    except socket.error, msg:
        logging.exception("Connection Failed!")
    else:
        logging.info("Connected to Server: %s" % dest_ip)

    return sock


def hexstr(s):
    return '-'.join('%02x' % ord(c) for c in s)


def dumb_fuzzing(dest_ip):
  sock = create_connection(dest_ip, dest_port)
  unitID = 0
  protoID = 0
  transID = 0
  lengthOfFunctionData = 1
  prevField = ""
  for functionCode in range(0,255):
    for functionData6 in range(0, 255):
      for functionData5 in range(0, 255):
        for functionData4 in range(0, 255):
          for functionData3 in range(0, 255):
            for functionData2 in range(0, 255):
              for functionData1 in range(0, 255):
                functionDataField = prevField + struct.pack(">B", functionData1)
                #print"%s" % hexstr(functionDataField)
                length = 2 + lengthOfFunctionData
                ModbusPacket = struct.pack(">H", transID) + \
                     struct.pack(">H", protoID) + \
                     struct.pack(">H", length) + \
                     struct.pack(">B", unitID) + \
                     struct.pack(">B", functionCode) + \
                     functionDataField
                logging.debug("%s" % hexstr(ModbusPacket))
                #print"%s" % hexstr(ModbusPacket)
                try:
                  sock.send(ModbusPacket)
                except socket.timeout:
                  logging.exception("Sending Timed Out!")
                except socket.error:
                  logging.exception("Sending Failed!")
                  sock.close()
                  sock = create_connection(dest_ip, dest_port)
                  logging.info("Try to Reconnect...")
                else:
                  logging.debug("Sent Packet: %s" % hexstr(ModbusPacket))
                  print "Sent: %s" % hexstr(ModbusPacket)
'''                      try:
                        data = sock.recv(1024)
                        print 'Received %s:' % repr(data)
                      except socket.timeout:
                        print ''
                      except socket.error:
                        sock.close()
                        sock = create_connection(dest_ip, dest_port)

  sock.close()
'''
def smart_fuzzing_with_user_input(dest_ip, msg):
    sock = create_connection(dest_ip, dest_port)
    strInput = msg
    dataSend = ""
    shortInput = ""
    cnt = 1
    for chInput in strInput:
    	shortInput += chInput
        if cnt%2 == 0:
           intInput = int(shortInput,16)
           dataSend += struct.pack(">B", intInput)
           shortInput = ""
        cnt += 1
    try:
      sock.send(dataSend)
      print 'sent: %s' % hexstr(dataSend)
    except socket.error:
      sock.close()
      print 'trying to create connection again'
      sock = create_connection(dest_ip, dest_port)
    try:
      dataRecv = sock.recv(1024)
      print >>sys.stderr, 'received: %s' % hexstr(dataRecv)
    except socket.timeout:
      print 'recv timed out!'
    except socket.error:
      sock.close()
      sock = create_connection(dest_ip, dest_port)
    sock.close()

def simulator(dest_ip):
    value1 = 0
    value2 = 100
    transID = 0
    while True:
      strTransID = "%0.4x" % transID
      strHex1 = "%0.4x" % value1
      msg1 = strTransID + "0000000B01060000" + strHex1
      smart_fuzzing_with_user_input(dest_ip, msg1)

      transID += 1
      strTransID = "%0.4x" % transID
      strHex2 = "%0.4x" % value2
      msg2 = strTransID + "0000000B01060001" + strHex2
      smart_fuzzing_with_user_input(dest_ip, msg2)

      value1 += 1
      value2 -= 1
      transID += 1
      if (value1 > 100):
        value1 = 0
      if (value2 < 0):
        value2 = 100
      time.sleep(0.3)

def smart_fuzzing_for_func08h(dest_ip):
    sock = create_connection(dest_ip, dest_port)
    transID = 0
    protocolID = 0
    length = 6
    unitID = 0
    funcCode = 8 # Diagnostic
    subFunction = 13 # sub function code start from 0x0000
    dataField = 0

    while True:
      packet = struct.pack(">H", transID) + struct.pack(">H", protocolID) + struct.pack(">H", length) + \
               struct.pack(">B", unitID) + struct.pack(">B", funcCode) + struct.pack(">H", subFunction) + \
               struct.pack(">H", dataField)
      try:
        sock.send(packet)
      except socket.error:
        sock.close()
        sock = create_connection(dest_ip, dest_port)
      try:
        dataRecv = sock.recv(1024)
      except socket.timeout:
        sys.stdout.write('1.time out\n')
      except socket.error:
        sock.close()
        sock = create_connection(dest_ip, dest_port)

      if len(dataRecv) > 0:
         print "Sent: %s" % hexstr(packet)
         print "Recv: %s" % hexstr(dataRecv)

#      if len(dataRecv) < 1:
#        sock.close()
#        sock = create_connection(dest_ip, dest_port)
#        try:
#          sock.send(packet)
#          print "Sent2: %s" % hexstr(packet)
#        except socket.error:
#          print 'FAILED TO SEND2'
#        try:
#          dataRecv = sock.recv(1024)
#          print "Recv2 : %s" % hexstr(dataRecv)
#        except socket.timeout:
#          sys.stdout.write('2.time out\n')
#        except socket.error:
#          print 'FAILED TO RECV2'

      transID = transID + 1
#      subFunction = subFunction + 1
      dataField = dataField + 1

def smart_fuzzing_for_func0Fh(dest_ip):
    sock = create_connection(dest_ip, dest_port)
    transID = 0
    protocolID = 0
    length = 8
    unitID = 0
    funcCode = 15 # Write Multiple coils
    startAddr = 0 # start from 0x0000
#    startAddr = 122 # start from 0xFFFF
    quantityOutputs = 8
    if (quantityOutputs % 8 == 0):
        byteCount = quantityOutputs / 8
    else:
        byteCount = quantityOutputs / 8 + 1
    value = 255

    loopCounter = 0
    while True:
      packet = struct.pack(">H", transID) + struct.pack(">H", protocolID) + struct.pack(">H", length) + \
               struct.pack(">B", unitID) + struct.pack(">B", funcCode) + struct.pack(">H", startAddr) + \
               struct.pack(">H", quantityOutputs) + struct.pack(">B", byteCount) + struct.pack(">B", value) + \
               struct.pack(">B", 255)*loopCounter
      try:
        sock.send(packet)
        print "Sent: %s" % hexstr(packet)
      except socket.error:
        sock.close()
        sock = create_connection(dest_ip, dest_port)
      try:
        dataRecv = sock.recv(1024)
        print "Recv : %s" % hexstr(dataRecv)
      except socket.timeout:
        sys.stdout.write('1.time out\n')
      except socket.error:
        sock.close()
        sock = create_connection(dest_ip, dest_port)

      if len(dataRecv) < 1:
        sock.close()
        sock = create_connection(dest_ip, dest_port)
        try:
          sock.send(packet)
          print "Sent2: %s" % hexstr(packet)
        except socket.error:
          print 'FAILED TO SEND2'
        try:
          dataRecv = sock.recv(1024)
          print "Recv2 : %s" % hexstr(dataRecv)
        except socket.timeout:
          sys.stdout.write('2.time out\n')
        except socket.error:
          print 'FAILED TO RECV2'

      transID = transID + 1
      loopCounter = loopCounter + 1

def smart_fuzzing_for_func10h(dest_ip):
    sock = create_connection(dest_ip, dest_port)
    transID = 0
    protocolID = 0
    length = 9
    unitID = 0
    funcCode = 16 # Write Multiple registers
#    startAddr = 0 # start from 0x0000
    startAddr = 122 # start from 0xFFFF
    quantityReg = 1
    byteCount = 2*quantityReg
    value = 65535

    loopCounter = 0
    while True:
      packet = struct.pack(">H", transID) + struct.pack(">H", protocolID) + struct.pack(">H", length) + \
               struct.pack(">B", unitID) + struct.pack(">B", funcCode) + struct.pack(">H", startAddr) + \
               struct.pack(">H", quantityReg) + struct.pack(">B", byteCount) + struct.pack(">H", value) + \
               struct.pack(">B", 255)*loopCounter
      try:
        sock.send(packet)
        print "Sent: %s" % hexstr(packet)
      except socket.error:
        sock.close()
        sock = create_connection(dest_ip, dest_port)
      try:
        dataRecv = sock.recv(1024)
        print "Recv : %s" % hexstr(dataRecv)
      except socket.timeout:
        sys.stdout.write('1.time out\n')
      except socket.error:
        sock.close()
        sock = create_connection(dest_ip, dest_port)

      if len(dataRecv) < 1:
        sock.close()
        sock = create_connection(dest_ip, dest_port)
        try:
          sock.send(packet)
          print "Sent2: %s" % hexstr(packet)
        except socket.error:
          print 'FAILED TO SEND2'
        try:
          dataRecv = sock.recv(1024)
          print "Recv2 : %s" % hexstr(dataRecv)
        except socket.timeout:
          sys.stdout.write('2.time out\n')
        except socket.error:
          print 'FAILED TO RECV2'

      transID = transID + 1
      loopCounter = loopCounter + 1
#    sock.close()

 

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
            sock.settimeout(0.2)
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
    print "modbus fuzzer v0.5"
    print ""
    print "Usage: python modFuzzer.py [-D] [destination_IP]"
    print "                           [-I] [destination_IP] [packet]"
    print "                           [-S] [IP_range]"
    print "                           [-SD] [IP_range]"
    print "                           [-S08] [destination_IP]"
    print "                           [-S0F] [destination_IP]"
    print "                           [-S10] [destination_IP]"
    print "                           [-SIM] [destination_IP]"
    print " "
    print "Commands:"
    print "Either long or short options are allowed."
    print "  --dumb    -D   Fuzzing in dumb way"
    print "  --input   -I   Fuzzing with given modbus packet"
    print "  --scan    -S   Scan the modbus device(s) in given IP range"
    print "  --sc_dumb -SD  Scan the device(s) and doing dumb fuzzing"
    print "  --f08     -F08 Fuzzing using function code 0x08"
    print "  --f0f     -F0F Fuzzing using function code 0x0F"
    print "  --f10     -F10 Fuzzing using function code 0x10"
    print "  --sim     -SIM Working in simulator mode"
#    print " "
#    print "Option:"
#    print "  --port    -p  Port number"
    print " "
    print "Example:"
    print "python modFuzzer.py -D 192.168.0.123"
#    print "python modFuzzer.py -D 192.168.0.123 -p 8888"
    print "python modFuzzer.py -I 192.168.0.23 0000000000060103000A0001"
    print "python modFuzzer.py -S 192.168.0.0/24"
    print "python modFuzzer.py -F10 192.168.0.0"
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
    smart_fuzzing_with_user_input(argv2, argv3)

elif (argv1=='-S') or (argv1=='--scan') or (argv1=='-SD'):       # scan device
    if argv1 =='-SD' :
        dumbflagset = 1 
    scan_device(argv2)

elif (argv1=='-F08') or (argv1=='--f08'): # smart fuzzing for function code 0x08
    smart_fuzzing_for_func08h(argv2)

elif (argv1=='-S0F') or (argv1=='--f0f'): # smart fuzzing for function code 0x0F
    smart_fuzzing_for_func0Fh(argv2)

elif (argv1=='-S10') or (argv1=='--f10'): # smart fuzzing for function code 0x10
    smart_fuzzing_for_func10h(argv2)

elif (argv1=='--sim') or (argv1=='--sim'):
    simulator(argv2)

sys.exit(0)
