from enum import Enum, unique
import math
import struct

@unique
class AesBlockmode(Enum):
    ECB = 0
    CBC = 1
    CTR = 2

class aes(object):

    blockSize = 16

    sbox =  [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
            0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
            0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
            0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
            0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
            0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
            0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
            0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
            0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
            0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
            0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
            0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
            0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
            0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
            0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
            0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
            0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
            0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
            0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
            0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
            0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
            0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
            0x54, 0xbb, 0x16]

    rsbox = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
            0x9e, 0x81, 0xf3, 0xd7, 0xfb , 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
            0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb , 0x54,
            0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
            0x42, 0xfa, 0xc3, 0x4e , 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
            0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 , 0x72, 0xf8,
            0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
            0x65, 0xb6, 0x92 , 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
            0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 , 0x90, 0xd8, 0xab,
            0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
            0x45, 0x06 , 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
            0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b , 0x3a, 0x91, 0x11, 0x41,
            0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
            0x73 , 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
            0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e , 0x47, 0xf1, 0x1a, 0x71, 0x1d,
            0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b ,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
            0xfe, 0x78, 0xcd, 0x5a, 0xf4 , 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
            0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f , 0x60,
            0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
            0x93, 0xc9, 0x9c, 0xef , 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
            0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 , 0x17, 0x2b,
            0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
            0x21, 0x0c, 0x7d]

    rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
            0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
            0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
            0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
            0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
            0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
            0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
            0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
            0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
            0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
            0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
            0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
            0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
            0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
            0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d]
            

    def subBytes(self, buff):
        for i in range(self.blockSize):
            buff[i] = self.sbox[buff[i]]
        return buff

    def rsubBytes(self, buff):
        for i in range(self.blockSize):
            buff[i] = self.rsbox[buff[i]]
        return buff

    def shiftRows(self, buff):
        buff[0:4]   = buff[0], buff[1], buff[2], buff[3]
        buff[4:8]   = buff[5], buff[6], buff[7], buff[4]
        buff[8:12]  = buff[10], buff[11], buff[8], buff[9]
        buff[12:16] = buff[15], buff[12], buff[13], buff[14]
        return buff

    def rshiftRows(self, buff):
        buff[0:4]   = buff[0], buff[1], buff[2], buff[3]
        buff[4:8]   = buff[7], buff[4], buff[5], buff[6]
        buff[8:12]  = buff[10], buff[11], buff[8], buff[9]
        buff[12:16] = buff[13], buff[14], buff[15], buff[12]
        return buff
        
    def galois_multiply(self, a, b):
        p = 0
        for i in range(8):
            # Detect constant term '1'
            if (b & 1):
                p ^= a
            # detect if x^8 term is about to be generated
            carry = a & 0x80
            # shift left
            a <<= 1
            a &= 0xff
            if (carry):
                a ^= 0x1B
            b >>= 1
        return p


    def mixColumnB(self, buff, b):
        a = bytearray(buff)
        g = self.galois_multiply
        buff[0] = g(a[0], b[0]) ^ g(a[3], b[1]) ^ g(a[2], b[2]) ^ g(a[1], b[3])
        buff[1] = g(a[1], b[0]) ^ g(a[0], b[1]) ^ g(a[3], b[2]) ^ g(a[2], b[3])
        buff[2] = g(a[2], b[0]) ^ g(a[1], b[1]) ^ g(a[0], b[2]) ^ g(a[3], b[3])
        buff[3] = g(a[3], b[0]) ^ g(a[2], b[1]) ^ g(a[1], b[2]) ^ g(a[0], b[3])
        return buff

    def mixColumn(self, buff):
        b = (2, 1, 1, 3)
        return self.mixColumnB(buff, b)

    def rmixColumn(self, buff):
        b = (14, 9, 13, 11)
        return self.mixColumnB(buff, b)

    def mixColumns(self, buff):
        for i in range(4):
            column = buff[i:i+self.blockSize:4] 
            column = self.mixColumn(column)
            buff[i:i+self.blockSize:4] = column
        return buff

    def rmixColumns(self, buff):
        for i in range(4):
            column = buff[i:i+self.blockSize:4] 
            column = self.rmixColumn(column)
            buff[i:i+self.blockSize:4] = column
        return buff

    def keyCore(self, t, r):
        o = t[1:] + t[:1]
        for i in range(4):
            o[i] = self.sbox[o[i]]
        o[0] ^= self.rcon[r]
        return o

    def expandKey(self, key):
        n = self.blockSize
        b = 176

        eKey = bytearray(b)
        size = 0
        for i in range(n):
            eKey[i] = key[i]
        size += n

        r = 1
        while size < b:
            t = eKey[size-4:size]
            if size % n == 0:
                t = self.keyCore(t, r)
                r += 1
            for i in range(4):
                eKey[size] = t[i] ^ eKey[size-n]
                size += 1
        return eKey

    def createRoundKey(self, expandedKey, roundKeyPointer):
        roundKey = bytearray(self.blockSize)
        # Swap around the columns
        for i in range(4):
            for j in range(4):
                roundKey[j*4+i] = expandedKey[roundKeyPointer + i*4 + j]
        return roundKey

    def addRoundKey(self, buff, roundKey):
        for i in range(self.blockSize):
            buff[i] ^= roundKey[i]
        return buff

    def initRound(self, buff, roundKey):
        buff = self.addRoundKey(buff, roundKey)
        return buff

    def singleRound(self, buff, roundKey):
        buff = self.subBytes(buff)
        buff = self.shiftRows(buff)
        buff = self.mixColumns(buff)
        buff = self.addRoundKey(buff, roundKey)
        return buff

    def finalRound(self, buff, roundKey):
        buff = self.subBytes(buff)
        buff = self.shiftRows(buff)
        buff = self.addRoundKey(buff, roundKey)
        return buff

    def initRoundInv(self, buff, roundKey):
        buff = self.addRoundKey(buff, roundKey)
        return buff

    def singleRoundInv(self, buff, roundKey):
        buff = self.rshiftRows(buff)
        buff = self.rsubBytes(buff)
        buff = self.addRoundKey(buff, roundKey)
        buff = self.rmixColumns(buff)
        return buff

    def finalRoundInv(self, buff, roundKey):
        buff = self.rshiftRows(buff)
        buff = self.rsubBytes(buff)
        buff = self.addRoundKey(buff, roundKey)
        return buff

    def createBlock(self, buff):
        block = bytearray(self.blockSize)
        # Set the block values, for the block:
        # a0,0 a0,1 a0,2 a0,3
        # a1,0 a1,1 a1,2 a1,3
        # a2,0 a2,1 a2,2 a2,3
        # a3,0 a3,1 a3,2 a3,3
        # the mapping order is a0,0 a1,0 a2,0 a3,0 a0,1 a1,1 ... a2,3 a3,3
        #
        # iterate over the columns
        for i in range(4):
            # iterate over the rows
            for j in range(4):
                block[(i+(j*4))] = buff[(i*4)+j]
        return block

    def expandBlock(self, block):
        output = bytearray(self.blockSize)
        # unmap the block again into the output
        for k in range(4):
            # iterate over the rows
            for l in range(4):
                output[(k*4)+l] = block[(k+(l*4))]
        return output

    def encryptBlock(self, buff, key):
        r = 10
        s = self.blockSize
        k = 0

        expandedKey = self.expandKey(key)
        block = self.createBlock(buff)
        block = self.initRound(block, self.createRoundKey(expandedKey, k))

        k += s
        for i in range(0, r-1):
            block = self.singleRound(block, self.createRoundKey(expandedKey, k))
            k += s
        block = self.finalRound(block, self.createRoundKey(expandedKey, k))
        
        return self.expandBlock(block)

    def decryptBlock(self, buff, key):
        r = 10
        s = self.blockSize
        k = r*s
        expandedKey = self.expandKey(key)
        block = self.createBlock(buff)
        block = self.initRoundInv(block, self.createRoundKey(expandedKey, k))
        k -= s
        for i in range(r-1):
            block = self.singleRoundInv(block, self.createRoundKey(expandedKey, k))
            k -= s
        block = self.finalRoundInv(block, self.createRoundKey(expandedKey, k))
        return self.expandBlock(block)

    def encryptECB(self, buff, key):
        s = self.blockSize
        blocks = len(buff) // s
        result = bytearray()
        k = 0
        for i in range(blocks):
            block = buff[k:k+s]
            result.extend(self.encryptBlock(block,key))
            k += s
        return result
        
    def decryptECB(self, buff, key):
        s = self.blockSize
        blocks = len(buff) // s
        result = bytearray()
        k = 0
        for i in range(blocks):
            block = buff[k:k+s]
            result.extend(self.decryptBlock(block,key))
            k += s
        return result

    def addLastBlock(self, block, iv):
        result = bytearray()
        # Do an XOR of the smallest length
        for i in range(0, min(len(block), len(iv))):
            result.append( block[i] ^ iv[i] )
        return result

    def encryptCBC(self, buff, key, iv):
        s = self.blockSize
        blocks = len(buff) // s
        result = bytearray()
        k = 0
        lastblock = iv
        for i in range(blocks):
            block = self.addLastBlock(buff[k:k+s], lastblock)
            lastblock = self.encryptBlock(block,key)
            result.extend(lastblock)
            k += s
        return result
        
    def decryptCBC(self, buff, key, iv):
        s = self.blockSize
        blocks = len(buff) // s
        result = bytearray()
        k = 0
        lastblock = iv
        for i in range(blocks):
            block = buff[k:k+s]
            decryptblock = self.decryptBlock(block,key)
            result.extend(self.addLastBlock(decryptblock, lastblock))
            lastblock = block
            k += s
        return result

    def getCtrKeyStream(self, block, key, nonce):
        keyStream = bytearray(self.blockSize)
        # convert counter into 64-bit counter
        ctr = bytearray(struct.pack("!Q", block))
        ctr.reverse() # Convert to little endian
        # Combine with the nonce
        keyStream[0:self.blockSize/2] = nonce[0:self.blockSize/2]
        keyStream[self.blockSize/2:self.blockSize] = ctr
        return keyStream

    def encryptCTR(self, buff, key, nonce, ctr = 0):
        s = self.blockSize
        # Here we can round up
        blocks = int(math.ceil(float(len(buff)) / float(s)))
        result = bytearray()
        k = 0
        
        for i in range(blocks):
            block = self.getCtrKeyStream(i + ctr, key, nonce)
            # Encrypt the counter + nonce
            block = self.encryptBlock(block, key)
            # XOR with the plaintext
            block = self.addLastBlock(buff[k:k+s], block)
            result.extend(block)
            k += s
        return result

    def decryptCTR(self, buff, key, nonce):
        # Encryption and decryption are the same!
        return self.encryptCTR(buff, key, nonce)

    def reencryptCTR(self, buff, key, nonce, offset, edit):
        cypherTotal = bytearray(len(buff))
        # Calculate the first block number
        blockNum = offset / self.blockSize
        # And the byte number within the block
        blockOffset = offset % self.blockSize
        # Create a new block with offset
        plain = bytearray(blockOffset)
        plain.extend(edit)
        # Encrypt the new plaintext
        cypherPart = self.encryptCTR(plain, key, nonce, blockNum)
        # Graft the newly encrypted data onto the original
        cypherTotal[:] = buff[:]
        cypherTotal[offset:offset + len(edit)] = cypherPart[blockOffset:blockOffset + len(edit)]
        
        return cypherTotal
