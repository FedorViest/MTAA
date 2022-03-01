#    Copyright 2014 Philippe THIRION
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import socketserver
import re
import string
import socket
# import threading
import sys
import time
import logging

#HOST, PORT = '192.168.0.115', 6000
rx_register = re.compile(b"^REGISTER")
rx_invite = re.compile(b"^INVITE")
rx_ack = re.compile(b"^ACK")
rx_prack = re.compile(b"^PRACK")
rx_cancel = re.compile(b"^CANCEL")
rx_bye = re.compile(b"^BYE")
rx_options = re.compile(b"^OPTIONS")
rx_subscribe = re.compile(b"^SUBSCRIBE")
rx_publish = re.compile(b"^PUBLISH")
rx_notify = re.compile(b"^NOTIFY")
rx_info = re.compile(b"^INFO")
rx_message = re.compile(b"^MESSAGE")
rx_refer = re.compile(b"^REFER")
rx_update = re.compile(b"^UPDATE")
rx_from = re.compile(b"^From:")
rx_cfrom = re.compile(b"^f:")
rx_to = re.compile(b"^To:")
rx_cto = re.compile(b"^t:")
rx_tag = re.compile(b";tag")
rx_contact = re.compile(b"^Contact:")
rx_ccontact = re.compile(b"^m:")
rx_uri = re.compile(b"sip:([^@]*)@([^;>$]*)")
rx_addr = re.compile(b"sip:([^ ;>$]*)")
# rx_addrport = re.compile("([^:]*):(.*)")
rx_code = re.compile(b"^SIP/2.0 ([^ ]*)")
rx_invalid = re.compile(b"^256\.256")
rx_invalid2 = re.compile(b"^256\.")
# rx_cseq = re.compile("^CSeq:")
# rx_callid = re.compile("Call-ID: (.*)$")
# rx_rr = re.compile("^Record-Route:")
rx_request_uri = re.compile(b"^([^ ]*) sip:([^ ]*) SIP/2.0")
rx_route = re.compile(b"^Route:")
rx_contentlength = re.compile(b"^Content-Length:")
rx_ccontentlength = re.compile(b"^l:")
rx_via = re.compile(b"^Via:")
rx_cvia = re.compile(b"^v:")
rx_branch = re.compile(b";branch=([^;]*)")
rx_rport = re.compile(b";rport$|;rport;")
rx_contact_expires = re.compile(b"expires=([^;$]*)")
rx_expires = re.compile(b"^Expires: (.*)$")

rx_busyhere = re.compile(b"Busy Here|here")
rx_trying = re.compile(b"Trying")
rx_calling = re.compile(b"Ringing")

# global dictionnary
recordroute = ""
topvia = ""
registrar = {}


def write_to_file(prompt, fromm, to, tag):
    time_now = time.strftime("%d %b %Y %H:%M:%S ", time.localtime())
    with open("log.txt", "a") as file:
        if prompt == "Call ended":
            file.write(prompt + " " + str(time_now) + " " + tag + " " + "\n\tby: " + str(fromm) + "\n\n")
        else:
            file.write(prompt + " " + str(time_now) + " " + tag + " " + "\n\tto: " + str(to) + " from:" + fromm + "\n")
        file.close()
    return


def change_message(change_str):
    return "SIP/2.0 " + change_str


def hexdump(chars, sep, width):
    while chars:
        line = chars[:width]
        chars = chars[width:]


def quotechars(chars):
    return ''.join(['.', c][c.isalnum()] for c in chars)


def showtime():
    logging.debug(time.strftime("(%H:%M:%S)", time.localtime()))


class UDPHandler(socketserver.BaseRequestHandler):

    def debugRegister(self):
        logging.debug("*** REGISTRAR ***")
        logging.debug("*****************")
        for key in registrar.keys():
            logging.debug("%s -> %s" % (key, registrar[key][0]))
        logging.debug("*****************")

    def changeRequestUri(self):
        # change request uri
        md = rx_request_uri.search(self.data[0])
        if md:
            method = md.group(1)
            uri = md.group(2)
            if uri in registrar:
                uri = "sip:%s" % registrar[uri][0]
                self.data[0] = "%s %s SIP/2.0" % (method, uri)

    def removeRouteHeader(self):
        # delete Route
        data = []
        for line in self.data:
            if isinstance(line, str):
                line = bytes(line, "utf-8")
            if not rx_route.search(line):
                data.append(line)
        return data

    def addTopVia(self):
        branch = ""
        data = []
        for line in self.data:
            if isinstance(line, str):
                line = bytes(line, "utf-8")
            if rx_via.search(line) or rx_cvia.search(line):
                md = rx_branch.search(line)
                if md:
                    branch = md.group(1)
                    via = "%s;branch=%sm" % (topvia, branch)
                    data.append(via)
                # rport processing
                if rx_rport.search(line):
                    text = "received=%s;rport=%d" % self.client_address
                    if isinstance(text, str):
                        text = bytes(text, "utf-8")
                    via = line.replace(b"rport", text)
                else:
                    text = "received=%s" % self.client_address[0]
                    via = "%s;%s" % (line, text)
                data.append(via)
            else:
                data.append(line)
        return data

    def removeTopVia(self):
        global topvia
        data = []
        for line in self.data:
            if rx_via.search(line) or rx_cvia.search(line):
                if isinstance(topvia, str):
                    topvia = bytes(topvia, "utf-8")
                if not line.startswith(topvia):
                    data.append(line)
            else:
                data.append(line)
        return data

    def checkValidity(self, uri):
        addrport, socket, client_addr, validity = registrar[uri]
        now = int(time.time())
        if validity > now:
            return True
        else:
            del registrar[uri]
            logging.warning("registration for %s has expired" % uri)
            return False

    def getSocketInfo(self, uri):
        addrport, socket, client_addr, validity = registrar[uri]
        return (socket, client_addr)

    def getDestination(self):
        destination = ""
        destination_str = ""
        for line in self.data:
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_uri.search(line)
                if md:
                    destination = "%s@%s" % (md.group(1), md.group(2))
                    destination_str = "%s@%s" % (md.group(1).decode(), md.group(2).decode())
                break
        return destination, destination_str

    def getOrigin(self):
        origin = ""
        origin_str = ""
        for line in self.data:
            if isinstance(line, str):
                line = bytes(line, "utf-8")
            if rx_from.search(line) or rx_cfrom.search(line):
                md = rx_uri.search(line)
                if md:
                    origin = "%s@%s" % (md.group(1), md.group(2))
                    origin_str = "%s@%s" % (md.group(1).decode(), md.group(2).decode())
                break
        return origin, origin_str

    def sendResponse(self, code):
        request_uri = "SIP/2.0 " + code
        self.data[0] = request_uri
        index = 0
        data = []
        for line in self.data:
            if isinstance(line, str):
                line = bytes(line, "utf-8")
            data.append(line)
            if rx_to.search(line) or rx_cto.search(line):
                if not rx_tag.search(line):
                    data[index] = b"%s%s" % (line, b";tag=123456")
            if rx_via.search(line) or rx_cvia.search(line):
                # rport processing
                if rx_rport.search(line):
                    text = "received=%s;rport=%d" % self.client_address
                    if isinstance(text, str):
                        text = bytes(text, "utf-8")
                    data[index] = line.replace(b"rport", text)
                else:
                    text = b"received=%s" % self.client_address[0]
                    data[index] = b"%s;%s" % (line, text)
            if rx_contentlength.search(line):
                data[index] = b"Content-Length: 0"
            if rx_ccontentlength.search(line):
                data[index] = b"l: 0"
            index += 1
            if line == "":
                break
        data.append(b"")
        text = b"\r\n".join(data)
        self.socket.sendto(text, self.client_address)
        showtime()
        logging.info("<<< %s" % data[0])
        logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))

    def processRegister(self):
        fromm = ""
        contact = ""
        contact_expires = ""
        header_expires = ""
        expires = 0
        validity = 0
        authorization = ""
        index = 0
        auth_index = 0
        data = []
        size = len(self.data)
        for line in self.data:
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_uri.search(line)
                if md:
                    fromm = "%s@%s" % (md.group(1), md.group(2))
            if rx_contact.search(line) or rx_ccontact.search(line):
                md = rx_uri.search(line)
                if md:
                    contact = md.group(2)
                else:
                    md = rx_addr.search(line)
                    if md:
                        contact = md.group(1)
                md = rx_contact_expires.search(line)
                if md:
                    contact_expires = md.group(1)
            md = rx_expires.search(line)
            if md:
                header_expires = md.group(1)

        if rx_invalid.search(contact) or rx_invalid2.search(contact):
            if fromm in registrar:
                del registrar[fromm]
            self.sendResponse("488 Not Acceptable Here")
            return
        if len(contact_expires) > 0:
            expires = int(contact_expires)
        elif len(header_expires) > 0:
            expires = int(header_expires)

        if expires == 0:
            if fromm in registrar:
                del registrar[fromm]
                self.sendResponse("200 0K")
                return
        else:
            now = int(time.time())
            validity = now + expires

        logging.info("From: %s - Contact: %s" % (fromm, contact))
        logging.debug("Client address: %s:%s" % self.client_address)
        logging.debug("Expires= %d" % expires)
        registrar[fromm] = [contact, self.socket, self.client_address, validity]
        self.debugRegister()
        self.sendResponse("200 0K")

    def processInvite(self):
        global recordroute
        logging.debug("-----------------")
        logging.debug(" INVITE received ")
        logging.debug("-----------------")
        origin, origin_str = self.getOrigin()
        if len(origin) == 0 or not origin in registrar:
            self.sendResponse("400 Bad Request")
            return
        destination, destination_str = self.getDestination()
        if len(destination) > 0:
            logging.info("destination %s" % destination)
            if destination in registrar and self.checkValidity(destination):
                socket, claddr = self.getSocketInfo(destination)
                # self.changeRequestUri()
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                # insert Record-Route
                if isinstance(recordroute, str):
                    recordroute = bytes(recordroute, "utf-8")
                data.insert(1, recordroute)
                text = b"\r\n".join(data)
                socket.sendto(text, claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))
                write_to_file("Call started", origin_str, destination_str,
                              text[text.find(b"Call-ID:"): text.find(b"Call-ID:") + 19].decode())
            else:
                self.sendResponse("480 Temporarily Unavailable")
        else:
            self.sendResponse("500 Server Internal Error")

    def processAck(self):
        global recordroute
        logging.debug("--------------")
        logging.debug(" ACK received ")
        logging.debug("--------------")
        destination, destination_str = self.getDestination()
        if len(destination) > 0:
            logging.info("destination %s" % destination)
            if destination in registrar:
                socket, claddr = self.getSocketInfo(destination)
                # self.changeRequestUri()
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                # insert Record-Route
                if isinstance(recordroute, str):
                    recordroute = bytes(recordroute, "utf-8")
                data.insert(1, recordroute)
                text = b"\r\n".join(data)
                socket.sendto(text, claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))

    def processNonInvite(self):
        global recordroute
        logging.debug("----------------------")
        logging.debug(" NonInvite received   ")
        logging.debug("----------------------")
        origin, origin_str = self.getOrigin()
        if len(origin) == 0 or not origin in registrar:
            self.sendResponse("400 Bad Request")
            return
        destination, destination_str = self.getDestination()
        if len(destination) > 0:
            logging.info("destination %s" % destination)
            if destination in registrar and self.checkValidity(destination):
                socket, claddr = self.getSocketInfo(destination)
                # self.changeRequestUri()
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                # insert Record-Route
                if isinstance(recordroute, str):
                    recordroute = bytes(recordroute, "utf-8")
                data.insert(1, recordroute)
                text = b"\r\n".join(data)
                socket.sendto(text, claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))
                if rx_bye.search(text):
                    write_to_file("Call ended", origin_str, destination_str,
                                  text[text.find(b"Call-ID:"): text.find(b"Call-ID:") + 19].decode())
            else:
                self.sendResponse("406 Not Acceptable")
        else:
            self.sendResponse("500 Server Internal Error")

    def processCode(self):
        origin, origin_str = self.getOrigin()
        if len(origin) > 0:
            logging.debug("origin %s" % origin)
            if origin in registrar:
                socket, claddr = self.getSocketInfo(origin)
                self.data = self.removeRouteHeader()
                data = self.removeTopVia()
                text = b"\r\n".join(data)
                socket.sendto(text, claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))

    def processRequest(self):
        # print "processRequest"
        if len(self.data) > 0:
            request_uri = self.data[0]

            if rx_busyhere.search(request_uri):
                self.data[0] = change_message("486 Obsadene")
            elif rx_trying.search(request_uri):
                self.data[0] = change_message("100 Skusam").encode()
            elif rx_calling.search(request_uri):
                self.data[0] = change_message("180 Zvonim").encode()

            print(self.data)
            if rx_register.search(request_uri):
                self.processRegister()
            elif rx_invite.search(request_uri):
                self.processInvite()
            elif rx_ack.search(request_uri):
                self.processAck()
            elif rx_bye.search(request_uri):
                self.processNonInvite()
            elif rx_cancel.search(request_uri):
                self.processNonInvite()
            elif rx_options.search(request_uri):
                self.processNonInvite()
            elif rx_info.search(request_uri):
                self.processNonInvite()
            elif rx_message.search(request_uri):
                self.processNonInvite()
            elif rx_refer.search(request_uri):
                self.processNonInvite()
            elif rx_prack.search(request_uri):
                self.processNonInvite()
            elif rx_update.search(request_uri):
                self.processNonInvite()
            elif rx_subscribe.search(request_uri):
                self.sendResponse("200 0K")
            elif rx_publish.search(request_uri):
                self.sendResponse("200 0K")
            elif rx_notify.search(request_uri):
                self.sendResponse("200 0K")
            elif rx_code.search(request_uri):
                self.processCode()
            else:
                logging.error("request_uri %s" % request_uri)
                # print "message %s unknown" % self.data

    def handle(self):
        # socket.setdefaulttimeout(120)
        data = self.request[0]
        self.data = data.split(b"\r\n")
        self.socket = self.request[1]
        request_uri = self.data[0]
        if rx_request_uri.search(request_uri) or rx_code.search(request_uri):
            showtime()
            logging.info(">>> %s" % request_uri)
            logging.debug("---\n>> server received [%d]:\n%s\n---" % (len(data), data))
            logging.debug("Received from %s:%d" % self.client_address)
            self.processRequest()
        else:
            if len(data) > 4:
                showtime()
                logging.warning("---\n>> server received [%d]:" % len(data))
                hexdump(data, ' ', 16)
                logging.warning("---")
