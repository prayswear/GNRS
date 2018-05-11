import socket
import logging.config
from protocol.icn_head import ICNPacket
import binascii
from util.util import int2byte

logging.config.fileConfig('logging.conf')
logger = logging.getLogger('myLogger')


class GnrsClient():

    def __init__(self, address, port):
        self.UDP_MTU = 1024
        self.gnrs_address = address
        self.gnrs_port = port

    def send(self, packet):
        data = packet.icn2byte()
        if len(data) > self.UDP_MTU:
            return None
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(data, (self.gnrs_address, self.gnrs_port))
        sock.settimeout(1)
        reply = None
        try:
            ack, remote_address = sock.recvfrom(self.UDP_MTU)
            print(ack)
            reply = ICNPacket()
            reply.byte2icn(ack)
            reply.print_packet()
        except socket.timeout:
            logger.error("Timeout")
        finally:
            sock.close()
        return reply

    def register(self, eid,na):
        icn_packet = ICNPacket()
        icn_packet.setHeader("c11e70000000000000000000000c11e7", "92500000000000000000000000000925", "00")
        cmd_type = binascii.a2b_hex("01")
        eid_hex = binascii.a2b_hex(eid)
        na_hex=binascii.a2b_hex(na)
        icn_packet.setPayload(cmd_type + eid_hex+na_hex)
        icn_packet.fill_packet()
        icn_packet.print_packet()
        reply = self.send(icn_packet)
        cmd_type=int(binascii.b2a_hex(reply.payload[:1]),16)
        ack=int(binascii.b2a_hex(reply.payload[17:18]),16)
        if cmd_type==2 and ack==1:
            return True
        else:
            return False

    def query_na(self, eid):
        icn_packet = ICNPacket()
        icn_packet.setHeader("c11e70000000000000000000000c11e7", "92500000000000000000000000000925", "00")
        cmd_type = binascii.a2b_hex("03")
        eid_hex=binascii.a2b_hex(eid)
        icn_packet.setPayload(cmd_type + eid_hex)
        icn_packet.fill_packet()
        reply = self.send(icn_packet)
        cmd_type=int(binascii.b2a_hex(reply.payload[:1]),16)
        na=binascii.b2a_hex(reply.payload[17:21]).decode("utf-8")
        if cmd_type==4:
            return na
        else:
            return None


if __name__ == "__main__":
    gnrs_address = "192.168.150.241"
    # gnrs_address = "127.0.0.1"
    gnrs_port = 22701
    client = GnrsClient(gnrs_address, gnrs_port)
    result = client.register("11111000000000000000000000022222","11223344")
    # result=client.query_na("11111000000000000000000000022222")
    logging.info(result)
