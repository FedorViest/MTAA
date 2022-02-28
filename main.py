import socketserver
import sipproxy

# Library from: https://github.com/tirfil/PySipFullProxy/blob/master/sipfullproxy.py

if __name__ == "__main__":
    HOST, PORT = '192.168.0.115', 6000
    sipproxy.recordroute = "Record-Route: <sip:%s:%d;lr>" % (HOST, PORT)
    sipproxy.topvia = "Via: SIP/2.0/UDP %s:%d" % (HOST, PORT)
    server = socketserver.UDPServer((HOST, PORT), sipproxy.UDPHandler)
    server.serve_forever()
