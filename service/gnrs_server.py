import socket
import threading
import logging.config
import binascii
from protocol.icn_head import ICNPacket
from util.db_tool import myDB
from util.util import int2byte

logging.config.fileConfig("logging.conf")
logger = logging.getLogger("myLogger")

class GnrsServer():

    def __init__(self,address,port):
        self.UDP_MTU = 1024
        self.address=address
        self.port=port

    def initDB(self,address,port,db_name,tbl_name):
        self.db_address=address
        self.db_port=port
        self.db_name=db_name
        self.tbl_name=tbl_name
        self.gnrsdb=myDB(self.db_address,self.db_port,self.db_name)


    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((self.address,self.port))
        logger.info("GNRS Server started...")
        while True:
            logger.info("Waiting for packet...")
            data, address = server_socket.recvfrom(self.UDP_MTU)
            logger.info("Recieve an UDP packet from " + str(address))
            logger.info(data)
            threading._start_new_thread(self.request_handler, (data, address))

    def request_handler(self,data,address):
        packet=ICNPacket()
        packet.byte2icn(data)
        packet.print_packet()
        payload=packet.payload
        cmd_type=int(binascii.b2a_hex(payload[:1]),16)
        reply=ICNPacket()
        reply.setHeader("92500000000000000000000000000925","c11e70000000000000000000000c11e7","00")
        if cmd_type==1:
            reply.setPayload(self.register(payload))
        elif cmd_type==3:
            reply.setPayload(self.query_na(payload))
        reply.fill_packet()
        reply.print_packet()
        self.send(reply,address)


    def register(self,data):
        eid=binascii.b2a_hex(data[1:17]).decode("utf-8")
        na=binascii.b2a_hex(data[17:21]).decode("utf-8")
        logging.info(na)
        result=self.gnrsdb.query(self.tbl_name,{"EID":eid})
        if result==None:
            self.gnrsdb.add(self.tbl_name,{"EID":eid,"NA":na})
        else:
            self.gnrsdb.update(self.tbl_name,{"EID":eid},{"NA":na})
        payload = binascii.a2b_hex("02" + eid + "01")
        return payload

    def query_na(self,data):
        eid=binascii.b2a_hex(data[1:17]).decode("utf-8")
        result = self.gnrsdb.query(self.tbl_name, {"EID": eid})
        if result == None:
            payload=binascii.a2b_hex("04"+eid+"00000000")
        else:
            payload=binascii.a2b_hex("04"+eid+result["NA"])
        return payload

    def send(self,packet,address):
        data = packet.icn2byte()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(data, address)
        sock.close()
