from service.gnrs_server import *
import logging.config

logging.config.fileConfig('logging.conf')
logger = logging.getLogger('myLogger')

if __name__ == '__main__':
    gnrs_ip, gnrs_port = '192.168.150.241', 22701
    # gnrs_ip, gnrs_port = '127.0.0.1', 22701
    db_ip, db_port = '127.0.0.1', 27017
    db_name="gnrs"
    tbl_name="GNRS_tbl"
    server=GnrsServer(gnrs_ip,gnrs_port)
    server.initDB(db_ip,db_port,db_name,tbl_name)
    server.gnrsdb.remove_all(tbl_name)
    server.start()