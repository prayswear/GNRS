import binascii

def int2byte(num,bit_len):
    num_hex=hex(num).replace("0x","")
    return "0"*(bit_len//4-len(num_hex))+num_hex
