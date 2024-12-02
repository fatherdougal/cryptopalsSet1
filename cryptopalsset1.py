import base64
from binascii import unhexlify, hexlify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()


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




test5 = unhexlify('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
goodchars= list(range(97,122))+[32]
def singlexorkey(y):
    for i in range(0,255):
        key=i.to_bytes(1,byteorder="little")
        sword = xor((key*34),y)
        # print(str(i)+ "="+str(sum(x in goodchars for x in sword)))
        rat= sum(x in goodchars for x in sword)/len(sword)
        if rat >= 0.78:
            print(sword)
            return(chr(i))

def singlexor(y):
    for i in range(0,255):
        key=i.to_bytes(1,byteorder="little")
        sword = xor((key*34),y)
        # print(str(i)+ "="+str(sum(x in goodchars for x in sword)))
        rat= sum(x in goodchars for x in sword)/len(sword)
        if rat >= 0.78:
            print(sword)

#singlexor(test5)
## cooking MCs like a pound of bacon

#with open('xored.txt') as fp:
#    contents = fp.read()
#    for i in contents.splitlines():
 #       singlexor(unhexlify(i))
        ## "now that the party is jumping"


def multixor(input,key):
    longkey = (key * ((len(input) // len(key)) + 1 ))
    return(xor(input,longkey))

test6 = b"""Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""


##print(hexlify(multixor(test6,b'ICE')))


def hammingdist(x,y):
    return(sum(bin(byte).count('1') for byte in xor(x,y)))

test7= b'this is a test'
test8= b'wokka wokka!!!'
#print(hammingdist(test7,test8))

#with open('s1c6.txt') as file:
 #   ciphertxt = base64.b64decode(file.read())
#for keysize in range(2,40):
 #   print(keysize)
  #  print((hammingdist(ciphertxt[0:keysize],ciphertxt[keysize:2*keysize])/keysize + hammingdist(ciphertxt[2*keysize:3*keysize],ciphertxt[3*keysize:4*keysize])/keysize)/2)
#keysize of 31, 29 18 ,13

def cypherbreaker(cypher):
    keysize = 29
    key = ("")
    xbytes = bytes()
    for i in range(0,keysize):
        keybits = cypher[i::keysize]
        #key += (singlexorkey(keybits))

    #print(key)
    ## my letters heuristic is quite simple so the key decoding didnt get it perfectly.
    ## best key was Termiharor X: Bring the noise, which is quite clearly actually going to be Terminator X: Bring the noise

with open('s1c6.txt') as file:
    ciphertxt = base64.b64decode(file.read())
    cypherbreaker(ciphertxt)

#print(multixor(ciphertxt,b"Terminator X: Bring the noise"))
## this decodes the message!


def ecbdecrypt(ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    data = decryptor.update(ciphertext) + decryptor.finalize()
    msg = data
    return msg.decode()

#with open('s1c7.txt') as file:
#    ciphertext = file.read()

#print(ecbdecrypt(base64.b64decode(ciphertext),b'YELLOW SUBMARINE'))
# I'm back and I'm ringin' the bell ...

with open('s1c8.txt') as file:
    ciphertextplural = [unhexlify(line.strip()) for line in file]


def repeatedblockchecker(ciphertext, blocksize=16):
    '''blocksize is in bytes'''
    if len(ciphertext) % blocksize != 0:
        raise Exception('ciphertext length is not a multiple of block size')
    else:
        num_blocks = len(ciphertext) // blocksize

    blocks = [ciphertext[i * blocksize:(i + 1) * blocksize] for i in range(num_blocks)]
    if len(set(blocks)) != num_blocks:
        return True
    else:
        return False

data = [ciphertext for ciphertext in ciphertextplural if repeatedblockchecker(ciphertext)]
print(data)
