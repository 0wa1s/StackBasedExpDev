import sys
import string
from struct import *
 
lower = string.ascii_lowercase
upper = string.ascii_uppercase
digits = string.digits
 
def create_pattern(size):
        pattern = ''
        j = k = l = 0
        for i in range(size):
                if(l == len(digits)):
                        l = 0
                        k+=1
                        if(k == len(upper)):
                                k = 0
                                j+=1
                pattern += upper[j]+lower[k]+digits[l]
                l+=1
        return pattern
     
def main():
        if len(sys.argv) < 2:
                print 'Usage : %s <length_pattern> ' % sys.argv[0]
                print '\t - If You Want Calculate junk size use : '
                print '\t\t %s 2000 0x68423768' % sys.argv[0]
        else:
                print '[+] Create pattern has length %s' % (sys.argv[1])
                pattern = create_pattern(int(sys.argv[1]))
                print pattern
                try:
                        if(sys.argv[2]):
                                key = pack('<I',int(sys.argv[2],16))
                                if key in pattern:
                                        print '[+] %s in Pattern => junk has length is %d' % (sys.argv[2],len(pattern[:pattern.rindex(key)]))
                                else:
                                        print '[!] Not calculate junk size'
                except IndexError:
                        pass #do nothing
if __name__ == '__main__':
        main()