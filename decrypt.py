aesByte = b'\xc9d\xa5\xd0Xy\x10F\xe2\x12\xb0h\x17\xce|\xab1\xa5\x97=l\x9dN\t\xc5%\xf6^\x9f\xa0\xb8\x90'

textByte = b'S\x1d\x16\x9d\xb1`\xdbB<fs\xfc#\xa3\x93\xbf\xec\xd0\x90K\x9f%\xa0\xf0\\\x9a\xf9\xcfm\xde74'

aesHex = aesByte.hex()
textHex = textByte.hex()

ivHex = textHex[:32]

ciphertextHex = textHex[32:]


print("Key      :", aesHex)
print("IV       :", ivHex)
print("Ciphertext:", ciphertextHex)

#https://gchq.github.io/CyberChef/