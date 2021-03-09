# RERLO

### 1.1 Opis

RELRO to technika polegająca na oznaczaniu sekcji związanych z GOT i PLT jako tylko do odczytu, co nie pozwala nadpisać tych sekcji.

Tablica GOT jest zapełniana podczas przebiegu programu. Kiedy po raz pierwszy funkcja z biblioteki współdzielnej zostanie wywołana GOT zawiera pointer powrotny do PLT, gdzie dynamiczny linker dostaje wywołany. Linker po odnalezieniu funkcji zapisuje ją w GOT. To jest `lazy binding` - raz znaleziona funkcja jest trzymana w pamięci w tablicy GOT, co pozwala zaoszczędzić czas.

Istnieja dwa rodzaje RELRO:
* partial RELRO - jedynie sekcja `.got` jest `read only` - co pozwala na nadpisanie adresu w `.got.plt` i wykonanie złośliwego kodu.
* full RELRO - cały GOT jest `read only`, co uniemożliwia ataki z nadpisaniem adresu w GOT.

Partial RELRO jest defaultowym zachowaniem `gcc` i nie wpływa na performance. Full RELRO jest jednak rozwiązaniem dość inwazyjnym. W przypadku ustawienia GOT jako `read only` w tablicy tej muszą już znajdować się wszystkie symbole, które są używane przez program. 

Znacząco wpływa to na czas startu aplikacji, bo linker musi na samym jej starcie uzupełnić cała tablice GOT

### 1.2 Proof of Concept - ret2libc