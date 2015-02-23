from hash import hash
from cryptobuffer import cryptobuffer

class hash_break():

    def __init__(self, algo):
        self.algo = algo

    def extend_hash(self, original_hash, original_message, new_message, verify_func, max_key_length = 64):

        for k in range(1, max_key_length):
            original_padding = self.algo.get_padding( len(original_message) + k )
            total_message = bytearray()
            total_message.extend(original_message)
            total_message.extend(original_padding)
            total_message.extend(new_message)

            new_padding = self.algo.get_padding( len(new_message), len(total_message) + k )

            extended_message = bytearray()
            extended_message.extend(new_message)
            extended_message.extend(new_padding)
            
            new_hash = self.algo.extend_hash( original_hash, extended_message )

            if (verify_func( total_message, new_hash )):
                return (total_message, new_hash)

        return (None, None)
