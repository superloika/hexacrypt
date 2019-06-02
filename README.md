# Hexacrypt


## About
Hexacrypt is a prototype of a mini algorithm for basic string encryption/decryption.
It has a password feature to enhance encryption security.


# Usage

Example:
	
	from hexacrypt import *
	
	msg = "Hello World"
	security_key = "secret123"
	
	encrypted_msg = Hexacrypt.encrypt(msg, security_key)
	print('encrypted msg: ', encrypted_msg)
	
	decrypted_msg = Hexacrypt.decrypt(encrypted_msg, security_key)
	print('decrypted msg: ', decrypted_msg)