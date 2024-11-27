import base64
from binascii import unhexlify, hexlify


def hexto64(hexy):
    binar = unhexlify(hexy)
    print(binar)
    return base64.b64encode(binar)


def xor(hexy1, hexy2):
    return bytes([x^y for (x,y) in zip(hexy1,hexy2)])


test1 = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
#print(hexto64(test))

test2 = "1c0111001f010100061a024b53535009181c"
test3= "686974207468652062756c6c277320657965"


test3= unhexlify(test3)
test2= unhexlify(test2)




test4 = unhexlify('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
goodchars= list(range(97,122))+[32]
for i in range(0,255):
    key=i.to_bytes(1,byteorder="little")
    sword = xor((key*34),test4)
   # print(str(i)+ "="+str(sum(x in goodchars for x in sword)))
    rat= sum(x in goodchars for x in sword)/len(sword)
    if rat >= 0.5:
        print(sword)
