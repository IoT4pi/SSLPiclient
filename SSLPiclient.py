#Test Client for SSLPi 
# you can use it and modify it to your own needs. 
# It is tested to work together with SSLPi Server.
#
#
#####################################################
#  Copyright (C) 2016 
#  IoT4pi <office@iot4pi.com>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the Apache License Version 2.0 (APLv2)
#  as published by http://www.apache.org/licenses/LICENSE-2.0 .
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  This product includes software developed by the OpenSSL Project
#  for use in the OpenSSL Toolkit. (http://www.openssl.org/)
#
#####################################################
import socket, ssl, pprint
import sys
import os

##############
#global variables
strIP='192.168.0.50'    #Ip Addreess or Domain Name
iPort=10023             #Port
strCert='server.pem'    #Certification File 
s=None                  #tcp Socket
ssl_sock=None           #ssl Socket


#######################
def init():
    global strIP
    global iPort
    global strCert
    i =len(sys.argv)
    #print "Num of parameter =" + str(i)
    x=0
    try:
        while x<i:
            #print 'parameter '+str(x) + ' : ' +  sys.argv[x]
            if sys.argv[x] == '-s':
                strIP= sys.argv[x+1]
            if sys.argv[x] == '-p':
                iPort= int(sys.argv[x+1])
            if sys.argv[x] == '-c':
                strCert=sys.argv[x+1]
            x+=1
    except:
        usage()
    print 'IP : ' +strIP
    print 'Port ' + str(iPort)
    print 'Cert ' + strCert
    setupSocket()      


#######################
def usage():
    sys.stdout = sys.stderr
    print "Usage: python SSLclient.py [-s Server] [-p port] [-c CertFile]"
    print "-s Server    IP Address or Domain Name"
    print "-p port      Port"
    print "-c CertFile  Certification File"
    sys.exit(2)

####################
def setupSocket():
    global s
    global ssl_sock
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Require a certificate from the server. We used a self-signed certificate
    # so here ca_certs must be the server certificate itself.
    try:    
        ssl_sock = ssl.wrap_socket(s,
                           server_side=False,
                           ca_certs=strCert,
                           cert_reqs=ssl.CERT_REQUIRED)
    except:
        print 'Error setting up SSL Socket'
        sys.exit(2)

    try:
        ssl_sock.connect((strIP, iPort))
    except:
        print 'Error connecting SSL Socket'
        sys.exit(2)
    main()

########################
def main():
    print repr(ssl_sock.getpeername())
    print ssl_sock.cipher()
    print pprint.pformat(ssl_sock.getpeercert())

    while True:
        try:
            print 'Send to Server : '
            line =raw_input()
            ssl_sock.write(line)
            recv=ssl_sock.recv(4096)
            print 'Receiv from Server : '
            print recv
        except ssl.SSLError as e:
            print "SSL Socket error:", sys.exc_info()[0]
            break
        except socket.error as e:
            print "Socket error:", sys.exc_info()[0]
            break
        except:
            print "Unexpected error:", sys.exc_info()[0]
            break

init()

