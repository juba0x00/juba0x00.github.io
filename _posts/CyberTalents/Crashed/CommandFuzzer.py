#!/usr/bin/env python3

import socket, argparse 

# colors 
RED = '\033[31m'
RESET = '\033[0m'
YELLOW = '\033[33m'
GREEN = '\033[32m'
CYAN = '\033[36m' 
BOLD = '\033[1m'

# creating argument parser object
ArgParser = argparse.ArgumentParser(
	description='DESCRIPTION:  Fuzzing Crashed challenge command ',
 	usage='./CommandFuzzer.py <ip> <port> <wordlist> [OPTIONS]',
 	add_help=True
 	)
     
# parsing the arguments
ArgParser.add_argument('ip', help="Specify the IP address")
ArgParser.add_argument('port', help="Specify the port number")
ArgParser.add_argument('wordlist', help="Specify the wordlist")
ArgParser.add_argument('-v', '--verbose', help='verbose mode', action='store_true')

args = ArgParser.parse_args()

# try to open the wordlist file and read its content 
try: 
    WordlistFile = open(args.wordlist, 'r')
    commands = WordlistFile.readlines() # commands with \n at the end 
    WordlistFile.close()
except Exception as FileError:
    print(FileError)
    exit(1)# exit the program, not wordlist found

commands = [command.replace('\n', '').upper() for command in commands] # remove \n and convert to uppercase 

for command in commands:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: # create socket object called 's'
            s.connect((args.ip, int(args.port))) # connect to the given IP and port 
            s.recv(1024) # receive the banner 
            s.send(bytes(command, "latin-1"))
            server_reponse = s.recv(1024).decode() # receive the response 

            if args.verbose:  # check verbosity mode
                print(f"Tesing: {GREEN}{command}{RESET} Command")
            
            if 'UNKNOWN COMMAND' not in server_reponse:  # check if the command exists 
                print(f"{RED}{BOLD}{command} {CYAN}command found")
                print(f"server response: {YELLOW}{server_reponse}{RESET}")
                
    except Exception as ConnectionError:# connection error 
        print(ConnectionError)
        exit(0)
