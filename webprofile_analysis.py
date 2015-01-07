from aesanalysis import aesanalysis
from cryptobuffer import cryptobuffer
from aes import aes

class webprofile_analysis(object):

    # This is a solution to challenge 14
    def cut_and_paste(self, func):
        x1 = cryptobuffer()
        x2 = cryptobuffer()

        # Assumptions
        # The blocksize is 16, AES ECB etc
        # ==> Can be calculated by hand
        # There are 6 bytes before the email string (email=)
        # ie 10 additional bytes to pad 1st block
        # ==> Could be automated?
        # The 'role=user' field is at the end of the string
        # pks7 padding is used
        print "\n---------------------------------"
        print "Cut and Paste ECB attack!"
        print "---------------------------------"

        # Creates a cypher where the last block
        # contains just the 'user' string and padding
        # Must be 13 bytes long
        s = "foooo@bar.com"
        x1.mBytes = func(s)
        print "Cypher with 13 byte user, last block to be replaced:"
        print x1.toHexBlocks(aes.blockSize)

        # Now we need a block with just 'admin' and
        # first some padding to fill the first block
        s = "\xaa" * 10
        # Now the admin string at the start of block 2
        s += "admin"
        # Now pks7 fill the 2nd block
        s += "\x0b" * 0x0b
        x2.mBytes = func(s)
        print "Middle block encrypted admin plus padding:"
        print x2.toHexBlocks(aes.blockSize)        

        # Cut and paste the last block of x1
        # with the second block of x2
        x1.mBytes[32:48] = x2.mBytes[16:32]
        print "Cut and paste last and middle blocks:"
        print x1.toHexBlocks(aes.blockSize)

        return x1.mBytes

    def getFlippedAdmin(self):
        userBytes  = cryptobuffer()
        # Two bytes to get to the end of a block
        userString =  "XX"
        # Our injected admin string
        userString += "&admin=true"
        userBytes.fromString(userString)

        print "Input user string:"
        print userBytes.toString()
        print userBytes.toHexBlocks(aes.blockSize)
        
        # Now flip the bits corresponding to the
        # & and the = so that they are not eaten
        # by the parser.
        userBytes.flipBit(3 * 8 - 1) # & to '
        userBytes.flipBit(9 * 8 - 1) # = to <

        print "User string with flipped bits:"
        print userBytes.toString()
        print userBytes.toHexBlocks(aes.blockSize)        
        return userBytes

    def cbc_bitflip(self, encrypt, hasAdmin):
        cyphertext = cryptobuffer()
        isAdmin = False

        print "\n---------------------------------"
        print "CBC Bit Flip Attack!"
        print "---------------------------------"

        userBytes = self.getFlippedAdmin()
        
        # Run the encryption 
        cyphertext.mBytes = encrypt(userBytes.toString())
        print "The encrypted block:"
        print cyphertext.toHexBlocks(aes.blockSize)

        print "Running admin search:"
        isAdmin = hasAdmin(cyphertext.mBytes)
        print "Decrpyted contains admin? ", isAdmin

        # After encryption, the user data (after the XX)
        # will appear in the third block. While decrypting,
        # CBC does an XOR of the last block, so we can
        # flip the bits in the previous block to recover
        # the & and = 
        cyphertext.flipBit(128 + 1 * 8 - 1) # ' to &
        cyphertext.flipBit(128 + 7 * 8 - 1) # < to =

        print "Flipping first bit:"
        print cyphertext.toHexBlocks(aes.blockSize)

        print "Running admin search with flipped bits:"
        # Now the first block will remain the same
        # The second block will be scrambled
        # The third block should contain our admin
        isAdmin = hasAdmin(cyphertext.mBytes)
        print "Decrpyted contains admin? ", isAdmin

        return isAdmin

    def ctr_bitflip(self, encrypt, hasAdmin):
        cyphertext = cryptobuffer()
        userBytes  = cryptobuffer()
        isAdmin = False

        print "\n---------------------------------"
        print "CTR Bit Flip Attack!"
        print "---------------------------------"

        userBytes = self.getFlippedAdmin()

        # Run the encryption 
        cyphertext.mBytes = encrypt(userBytes.toString())
        print "The encrypted block:"
        print cyphertext.toHexBlocks(aes.blockSize)

        print "Running admin search:"
        isAdmin = hasAdmin(cyphertext.mBytes)
        print "Decrpyted contains admin? ", isAdmin

        # In the case of CTR, we just need to flip the
        # same bits in the cyphertext (with an offset for
        # prepended text) as CTR is just an XOR
        cyphertext.flipBit(128 * 2 + 1 * 8 - 1) # ' to &
        cyphertext.flipBit(128 * 2 + 7 * 8 - 1) # < to =

        print "Flipping first bit:"
        print cyphertext.toHexBlocks(aes.blockSize)

        print "Running admin search with flipped bits:"
        # Now the first block will remain the same
        # The second block will be scrambled
        # The third block should contain our admin
        isAdmin = hasAdmin(cyphertext.mBytes)
        print "Decrpyted contains admin? ", isAdmin

        return isAdmin

    # This is the solution to challenge 27
    def cbc_key_as_iv_attack(self, encrypt, decrypt):
        cyphertext = cryptobuffer()
        plain = cryptobuffer()
        plain1 = cryptobuffer()
        plain3 = cryptobuffer()
        key = cryptobuffer()

        print "\n---------------------------------"
        print "CBC Key recovery with Key as IV"
        print "---------------------------------"

        # Arbitrary user string
        userString = "Hip to the hippy to the hip hip hop"
       
        # Run the encryption (should be at least three blocks long)
        cyphertext.mBytes = encrypt(userString)

        # Now modify the message 
        # C_1, C_2, C_3 -> C_1, 0, C_1
        cyphertext.mBytes[16:32] = '\x00' * 16
        cyphertext.mBytes[32:48] = cyphertext.mBytes[0:16]

        print cyphertext.toHexBlocks(aes.blockSize)

        # Try to decrypt, this should throw as there
        # are non-ASCII bytes present
        try:
            decrypt(cyphertext.mBytes)
        except ValueError as e:
            # Recover the plaintext
            plain.fromBase64(str(e))
            print "Recovered plaintext from error:"
            print plain.toPrintable()
            # Now extract the IV, which is also the key:
            # P'_1 XOR P'_3
            plain1.mBytes = plain.mBytes[0:16]
            plain3.mBytes = plain.mBytes[32:48]
            key = plain1.xor(plain3)
            print "Extracted Key:"
            print key.toHex()

        return key.mBytes


    def cbc_padding_attack(self, ivBytes, encryptedBytes, ispadded):
        cypher = cryptobuffer()
        previous = cryptobuffer()
        iv = cryptobuffer()
        plain = cryptobuffer()

        print "\n---------------------------------"
        print "CBC Padding Oracle Attack!"
        print "---------------------------------"

        iv.mBytes = ivBytes
        cypher.mBytes = encryptedBytes
        
        print "Original Cypher text:"
        print cypher.toHexBlocks(aes.blockSize)
        padOk = ispadded(cypher.mBytes)
        print "padding valid: ", padOk
        
        nBlocks = len(cypher.mBytes) / aes.blockSize
        previous = iv

        for b in range(0, nBlocks):
            b1 = b  * aes.blockSize
            b2 = b1 + aes.blockSize

            # P2 = B1 ^ I2
            # Valid padding when:
            # P2[16] = 1, loop over to find B1[16] -> can infer I2[16]
            P2 = cryptobuffer()
            I2 = cryptobuffer()
            I2.mBytes[0:16] = "\x00" * 16
            B1 = cryptobuffer()
            B1.mBytes[0:16] = "\xaa" * 16
            B2 = cryptobuffer()
            B2.mBytes[0:16] = cypher.mBytes[b1:b2]

            for j in range(0, 16):
                padOk = False
                padValue = '\x00'
                for i in range(0, 256):
                    cypherhack = cryptobuffer()
                    cypherhack.mBytes[0:16]  = B1.mBytes
                    cypherhack.mBytes[16:32] = B2.mBytes
                    cypherhack.mBytes[15-j] = i
                    padOk = ispadded(cypherhack.mBytes)
                    if (padOk):
                        padValue = i
                        break
                if (padOk):
                    # We have found a valid padding bit, value i
                    print "Block: ", b, " Byte: ", j, " padding valid: ", padOk, " value: ", i
                    # Infer the intermediate state, as we know the padding
                    I2.mBytes[15-j] = padValue ^ (j + 1)
                    # Infer the plaintext for intermediate state and iv
                    P2 = I2.xor(previous)
                    print "IV:  ", I2.toHex()
                    print "txt: ", P2.toHex()
                    # Now set B1 for the next byte(s)
                    for k in range(15-j, 16):
                        B1.mBytes[k] = I2[k] ^ (j + 2)
                else:
                    print "Padding unknown!"
                    break
            plain.mBytes[b1:b2] = P2.mBytes
            previous = B2

        plain.stripPks7Padding()
        print "Decrypted message:"
        print plain.toHexBlocks(aes.blockSize)
        print plain.toString()
        
        return plain.mBytes

