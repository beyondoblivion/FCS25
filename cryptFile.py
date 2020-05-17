#!/usr/bin/env python3

import crypt
from sys import argv
from os import rename
from os.path import getsize,isfile
import hashlib
import time

import struct

blockSize = 128
keySize = blockSize // 2

def mainE(fullFileName):
	password = input('Password:').encode('utf-8')

	sha512 = hashlib.sha512()
	sha512.update(password)

	salt = int(time.time()).to_bytes(8,byteorder = 'little')

	sha512.update(salt) #just add a touch of salt~

	encryptFile(fullFileName,salt,sha512.digest())

def mainD(fullFileName):
	password = input('Password:').encode('utf-8')

	decryptFile(fullFileName,password)

class encryptedFileReader:
	def __init__(self,fileName,password):
		self.inputFile = open(fileName,'rb')
		print(self.inputFile)
		self.fileName = fileName
		self.buffer = b''

		self.hashKey = b'\x00' * keySize

		self.sha = hashlib.sha512() #just for block hasing, not for the key

		sha = hashlib.sha512() #just for the key, not for block hashing

		sha.update(password)

		sha.update(self.inputFile.read(8))

		self.key = sha.digest()

		keyFromFile = self.read(keySize)

		assert self.key == keyFromFile, 'Incorrect Password'

	def __del__(self):
		self.inputFile.close()

	def bytesRemaining(self):
		fileSize = getsize(self.fileName)
		filePointer = self.inputFile.tell()
		return fileSize - filePointer + len(self.buffer)

	def read(self,byteCount):
		while len(self.buffer) < byteCount:
			self.buffer += self.__doRead()

		ret = self.buffer[:byteCount]
		self.buffer = self.buffer[byteCount:]

		return ret

	def __doRead(self):
		block = self.inputFile.read(blockSize)

		ret = crypt.decrypt512(block,crypt.xor(self.key,self.hashKey))

		self.sha.update(ret)

		self.hashKey = self.sha.digest()

		return ret

def decryptFile(fullFileName,key):
	i = 0
	while isfile(str(i)+'.decrypt'):
		i += 1

	decryptedFileName = str(i)+'.decrypt'

	with open(decryptedFileName, 'xb') as fo:
		efr = encryptedFileReader(fullFileName,key)

		lastBlockSize = efr.read(1)[0]

		fileName = b''

		while True:
			b = efr.read(1)
			if b == b'\x00':
				break
			fileName += b

		fileName = fileName.decode('utf-8')

		headerSize = len(fileName) + 2 #lastBlockSize (1 byte) + null character (1 byte)

		bytesReadSoFar = blockSize - headerSize % blockSize

		fo.write(efr.read(bytesReadSoFar))

		bytesRemaining = efr.bytesRemaining()

		for i in range(bytesRemaining//blockSize):
			fo.write(efr.read(blockSize))
		else:
			fo.write(efr.read(lastBlockSize))

	rename(decryptedFileName,fileName)
	

class encryptedFileWriter:
	def __init__(self,key,salt):
		self.byteBuffer = b''
		self.key = key
		self.hashKey = b'\x00' * keySize

		self.sha = hashlib.sha512()

		i = 0
		while isfile(str(i)+'.crypt'):
			i += 1

		self.outputFile = open(str(i)+'.crypt','xb')

		self.outputFile.write(salt)

		self.write(key)

	def __del__(self):
		self.outputFile.close()

	def write(self,b):
		if b == None and len(self.byteBuffer) != 0:
			toEncrypt = self.byteBuffer + b'\x00' * (blockSize - len(self.byteBuffer))

			self.__doWrite(toEncrypt)

			self.byteBuffer = b'' #in case more needs to be written
		else:
			self.byteBuffer = self.byteBuffer + b

			while len(self.byteBuffer) >= blockSize:
				toEncrypt = self.byteBuffer[:blockSize]
				self.byteBuffer = self.byteBuffer[blockSize:]

				self.__doWrite(toEncrypt)

	def __doWrite(self,toEncrypt):
		self.sha.update(toEncrypt)

		block = crypt.encrypt512(toEncrypt,crypt.xor(self.key,self.hashKey))

		self.hashKey = self.sha.digest()

		self.outputFile.write(block)

def encryptFile(fullFileName,salt,key):
	with open(fullFileName, 'rb') as fi:
		lastIdx = -fullFileName[::-1].index('/')
		address = fullFileName[:lastIdx]
		fileName = fullFileName[lastIdx:]

		try:
			fileSize = getsize(fullFileName) #includes the header size
		except FileNotFoundError:
			print('File not found')
			exit(1)

		fileNameBytes = fileName.encode('utf-8') + b'\x00'

		lastBlockSize = (len(fileNameBytes) + fileSize + 1) % blockSize

		header = lastBlockSize.to_bytes(1,byteorder = 'little') + fileNameBytes

		bytesReadSoFar = blockSize - len(header) % blockSize

		d = header + fi.read(bytesReadSoFar)

		efw = encryptedFileWriter(key,salt)

		efw.write(d)

		bytesRemaining = fileSize - bytesReadSoFar

		for i in range(bytesRemaining//blockSize):
			efw.write(fi.read(blockSize))
		else:
			efw.write(fi.read(bytesRemaining%blockSize))
			efw.write(None)

if __name__ == '__main__':
	assert len(argv) >= 3, 'cryptFile.py [-e/-d] [Filename]'
	option = argv[1]
	if option == '-e':
		mainE(argv[2])
	elif option == '-d':
		mainD(argv[2])
