# hexacrypt.py
# Hexacrypt
# Basic String Encryption/Decryption Tool
# Author: superloika (superloika.github.io)

class Hexacrypt:
    def __init__(self):
        super(Hexacrypt, self).__init__()

    # ENCRYPTION
    def encrypt(str_to_encrypt, str_key="H3x4Cryp+"):
        """Author: Kaloi"""
        if (type(str_to_encrypt) not in (str, chr) or
                    type(str_key) not in (str, chr)):
            raise Exception("All args must be a string.")
        str_to_encrypt = str(str_to_encrypt)
        j = -1
        key_len = len(str_key)
        str_len = len(str_to_encrypt)
        result = ""

        try:
            if key_len == 0:
                str_key = "H3x4Cryp+"
                key_len = len(str_key)
            if str_len == 0:
                # print("No string to encrypt.")
                return result
            else:
                for i in range(str_len):
                    if i < key_len:
                        j += 1
                    else:
                        j = 0
                    xored = ord(str_to_encrypt[i]) \
                            ^ ord(str_key[j])
                    result += hex(xored)
        except Exception as e:
            print("Encryption error: " + str(e))
        # return "ERROR"
        return result

    # DECRYPTION
    def decrypt(hexadecimal_str, str_key="H3x4Cryp+"):
        """Author: Kaloi"""
        if (type(hexadecimal_str) not in (str, chr) or
                    type(str_key) not in (str, chr)):
            raise Exception("All args must be a string.")
        lst_str = hexadecimal_str.split("0x")
        lst_len = len(lst_str)
        key_len = len(str_key)
        j = -1
        result = ""
        try:
            if key_len == 0:
                str_key = "H3x4Cryp+"
                key_len = len(str_key)

            if lst_len == 1:
                # print("Unable to parse hexadecimal string.")
                return result
            else:
                for i in range(1, lst_len):
                    if i <= key_len:
                        j += 1
                    else:
                        j = 0
                    xored = int(eval("0x" + lst_str[i])) \
                            ^ ord(str_key[j])
                    result += chr(xored)
        except Exception as e:
            print("Decryption error: " + str(e))
        # return "ERROR"
        return result
