# Stack canary

### 1.1 Opis

Kanarek jest mechanizmem zabezpieczenia stosu. Stara się on zapobiegać zmianie wykonania programu za pomocą nadpisywanie elementów na stosie.

Stack canary albo security cookie to losowa wartość zapisywana na stosie przed adresem powrotu. Przed powrotem wartość ta jest sprawdzana. Jeżeli uległa zmianie przerywane jest działanie programu.

Wartości kanarka mogą być generowane w różny sposób. Mogą to być wartości zawierające elementy takie jak `null byte` czy `terminator chars`, aby zapobiegać nadpisaniu kanarka po nadpisaniu powrotu. W przypadku przepełnienia bufora zapisanie takich znaków jest dość trudne przy użyciu danych funkcji.

Dość popularną strategią jest generacja kanarka w losowy sposób przy inicjalizacji programu i zapis go w zmiennych globalnych. Oczywiście odczytanie takiego kanarka może być możliwe dlatego często jest on paddowany pustymi stronami.

Istnieją też tak zwane `XOR canaries`, czyli kanarki, których wartość to XOR paru losowo wybranych wartości z programu. Dzięki temu nadpisanie takiego kanarka graniczy z cudem.

Jest to defaultowa opcja kompilatora `gcc`, można ją wyłączyć flagą `-fno-stack-protector`. Ochronę funkcji z buforami większymi niż 8 bajtów i używającymi `alloca` włącza `-fstack-protector`. A ochronę wszystkich funkcji włącza `-fstack-protector-all`.

Podobnie zachowuje się `clang`.


### Proof of concept

Kanarek jest dobra metodą obrony przed atakami typu `ASLR & PIE/exploit_1`. Ataki bazujące na nadpisaniu adresu powrotu są dobrze łatane przez kanarka stosu. Jest to lepsza metoda niż ASLR, bo w 100% skuteczna.

Oczywiście wyciek pamięci (`arbitrary read`) pozwala bardzo łatwo obejść kanarka po prostu nadpisując w jego miejsce odpowiednią wartość.

Kod aplikacji podatnej jest taki sam, jaki  i exploit.

```c
// gcc vuln.c -no-pie -std=c99 -m32 -fno-stack-protector -z execstack -w -o vuln.o

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void secret() {
system("sh");
}

void ask_for_name()
{
char name[12] = {0};
puts("What's your name?");
gets(name);
printf("Hi %s!\n", name);
}

int main()
{
ask_for_name();
return 0;
}
```
Exploit:
```python
from pwn import *

p = process("./vuln.o")

p.readuntil("What's your name?\n")

name = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOO"

p.sendline(name)
```

W tym przypadku przy kompilacji z kanarkiem