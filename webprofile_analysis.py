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

    def cbc_bitflip(self, encrypt, hasAdmin):
        cyphertext = cryptobuffer()
        userBytes  = cryptobuffer()
        isAdmin = False

        print "\n---------------------------------"
        print "CBC Bit Flip Attack!"
        print "---------------------------------"


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

    def cbc_padding_attack(self, filename, encrypt, ispadded):
        cypher = cryptobuffer()
        previous = cryptobuffer()
        iv = cryptobuffer()

        print "\n---------------------------------"
        print "CBC Padding Oracle Attack!"
        print "---------------------------------"

        iv_and_cypher = encrypt(filename)
        iv.mBytes = iv_and_cypher[0]
        cypher.mBytes = iv_and_cypher[1]
        
        print "Original Cypher text:"
        print cypher.toHexBlocks(aes.blockSize)
        padOk = ispadded(cypher.mBytes)
        print "padding valid: ", padOk
        
        previous = iv

        for j in range(0, 16):
            cypherhack = cryptobuffer()
            # Take the first block of the cypher        
            cypherhack.mBytes[0:16]  = "\xaa" * 16
            cypherhack.mBytes[16:32] = cypher.mBytes[0:16]

            for i in range(0, 256):
                cypherhack.mBytes[15-j] = i
                padOk = ispadded(cypherhack.mBytes)
                print cypherhack.toHexBlocks(aes.blockSize)
                print "padding valid: ", padOk, " byte: ", j, " value: ", i
                if (padOk):
                    break
