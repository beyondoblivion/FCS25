#!/usr/bin/env python3

import hashlib

byteorder = 'little'
length = 32 * 2 #32 bytes == 256 bits,64 bytes == 512 bits

def main():
	key = b'\x00' * length #place 256/512 bit key here

	#the data should be twice as long as the key (256/512 bit key => 512/1024 bit data block)
	message = b''

	message = message + b'\x00'*(length*2-len(message))

	encryptedMessage = encrypt512(message,key)
	print('Encrypted:\n'+str(encryptedMessage))

	decryptedMessage = decrypt512(encryptedMessage,key)
	print('Decrypted:\n'+str(decryptedMessage))

#rotates to the left (negative numbers shift to the right)
def rotate(data,amount,bitSize):
	amount = amount % bitSize
	#data = data % (2**bitSize)
	if amount == 0:
		return data
	else:
		amount = bitSize - amount
		c = data%(2**amount)
		r = data>>amount
		r = r | (c<<(bitSize - amount))
		return r

def rotateBytes(data,amount):
	d = int.from_bytes(data,byteorder = byteorder)
	r = rotate(d,amount,len(data)*8)
	return r.to_bytes(len(data),byteorder = byteorder)

def xor(a,b):
	ai = int.from_bytes(a,byteorder = byteorder)
	bi = int.from_bytes(b,byteorder = byteorder)
	return (ai ^ bi).to_bytes(len(a),byteorder = byteorder)

def doRound256(l,r,k):
	sha256 = hashlib.sha256()
	sha256.update(xor(r,k))
	nl = xor(l,sha256.digest())
	return nl

def decrypt256(data,key):
	assert len(data) == 64,'Block is not the proper size (512 bits)'
	assert len(key) == 32,'Key is not the proper size (256 bits)'
	l = data[:len(data)//2]
	r = data[len(data)//2:]
	for i in range(64):
		key = rotateBytes(key,-4)
		l,r = r,doRound256(l,r,key)
	return r+l

def encrypt256(data,key):
	assert len(data) == 64,'Block is not the proper size (512 bits)'
	assert len(key) == 32,'Key is not the proper size (256 bits)'
	l = data[:len(data)//2]
	r = data[len(data)//2:]
	for i in range(64):
		l,r = r,doRound256(l,r,key)
		key = rotateBytes(key,4)
	return r+l

def doRound512(l,r,k):
	sha512 = hashlib.sha512()
	sha512.update(xor(r,k))
	nl = xor(l,sha512.digest())
	return nl

def decrypt512(data,key):
	assert len(data) == 128,'Block is not the proper size (1024 bits)'
	assert len(key) == 64,'Key is not the proper size (512 bits)'
	l = data[:len(data)//2]
	r = data[len(data)//2:]
	for i in range(64):
		key = rotateBytes(key,-8)
		l,r = r,doRound512(l,r,key)
	return r+l

def encrypt512(data,key):
	assert len(data) == 128,'Block is not the proper size (1024 bits)'
	assert len(key) == 64,'Key is not the proper size (512 bits)'
	l = data[:len(data)//2]
	r = data[len(data)//2:]
	for i in range(64):
		l,r = r,doRound512(l,r,key)
		key = rotateBytes(key,8)
	return r+l

if __name__ == '__main__':
	main()
