# Info 
# Start with: python SSLPiclient_V1_1.py -s localhost -p 10023 -c ../Cert/server.pem
#        python SSLPiclient_V1_1.py -s ineltro-halmer.firewall-gateway.net -p 10023 -c ../Cert/server.pem

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
import threading

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


#Creation of Threating Lock
threadLock = threading.Lock()
###############################
#Class for Receiving messages
class myThread (threading.Thread,):
    global ssl_sock
    def __init__(self, threadID, name, socket):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        #self.socket = socket
        self.isrunning=True

    def run(self):
        print "Starting " + self.name
        #Waits a given Time in seconds for
        #receiving a UDP Packet, if nothing happens
        #an exeption error occours
        #self.socket.settimeout(1)
        # Get lock to synchronize threads
        while 1:
            if self.isrunning==True:
                #print "True"
                
                #read_socket(self.socket)
                #recv=self.socket.recv(1028)
                recv=ssl_sock.recv(4096)
                if recv is None:
                    threadLock.acquire()
                    print 'Receiv is null '
                    threadLock.release()
                    continue
                if recv != '':
                    threadLock.acquire()
                    print 'Receiv from Server : '
                    threadLock.release()
                    print recv
                # Free lock to release next thread
                
            else:
                #print "False"
                break
    def stop(self):
        self.isrunning=False
        #print "Stopping " + self.name + ' sent !'
        



########################
def main():
    global ssl_sock
    print repr(ssl_sock.getpeername())
    print ssl_sock.cipher()
    print pprint.pformat(ssl_sock.getpeercert())

    ########
    # Create new threads
    thread1 = myThread(1, "Thread-1", ssl_sock)
    print 'threat should be created'
    # Start new Threads
    thread1.start()

    while True:
        try:
            threadLock.acquire()
            print 'Send to Server : '
            threadLock.release()
            line =raw_input()
            ssl_sock.write(line)
            
            #recv=ssl_sock.recv(4096)
            #print 'Receiv from Server : '
            #print recv
        except ssl.SSLError as e:
            print "SSL Socket error:", sys.exc_info()[0]
            break
        except socket.error as e:
            print "Socket error:", sys.exc_info()[0]
            break
        except:
            print "Unexpected error:", sys.exc_info()[0]
            break
    ##############
    # Wait for end of Threat
    thread1.stop()
    thread1.join()
    print 'End of programm'

init()

