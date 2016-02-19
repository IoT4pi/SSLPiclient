# SSLPiclient
The SSLPi test client

Copy  the file server.pem from the raspberry pi to your client.  
This file you have to copy and
provide your clients with it. This one is the key to establish a communication with the server. 

Without it, the server would reject any communication attempt.    

To start the client type

$ python SSLclient.py -s „Your_Serveraddress“ -p „PortNumber“-c server.pem

The command and options are
     $ python SSLclient.py [Option] 
      with [Option] 
       -s Server    IP address or Domain Name 
       -p port      Port Number
       -c CertFile  certificate file (also specify the full path if the cert file isn't in the same directory)


if now options are specified the programm will take following default values:

-s Server   = '192.168.0.50' 
-p port     = 10023 
-c CertFile = 'server.pem'
An example for a typical call:

 $ python SSLclient.py -s iot4pi.com -p 10023 -c server.pem
  
