# Fortify source

### 1.1 Opis

Technika `fortify source` polega na wykrywaniu przepełnienia buffora w `libc`. 

`Fortify source` jest wywoływane flagą `-D_FORTIFY_SOURCE={1,2}` gdzie `1,2` oznacza poziom zabezpieczeń.

Flaga ta działa tylko jeżeli obecna jest też flaga `-O1` lub wyższa.

`Libc` zawiera funkcję, które są wrapperami na funkcje, które są niebezpieczne, ale przyjmującymi argument oznaczający długość bufora. Dla przykładu funkcja:

```c
__memcpy_chk(void * dest, const void * src, size_t len, size_t destlen)
```

Funkcje te nie powinny być wywoływane przez użytkownika, są one używane właśnie w `fortify source`. Kiedy kompilator nie może dowieść, że funkcja nie posiada błedu, zamienia ją na jej bezpieczny odpowiednik.

Zapewnie to `run-time` protekcje przed przepełnieniem bufora.

Długość bufora obliczana jest za pomocą funkcji `__builtin_object_size()`, która zwraca bajty pozostające w strukturze. Jeżeli w czasie kompilacji nie znana jest wielkość to długością jest `(size_t) -1`.

Różnice w poziomie 1 i 2 określa to jak liczone są pozostałe bajty w powyższej funkcji. Rozważmy dana strukturę:

```c
struct test
{
    char test1[5];
    char test2[5];
}
```

W tym przypadku zapisywanie do `test1` wiecej niż 5 bajtów może być zdefiniowanym zachowanie programu, albo błędem. Dla opcji `1` pisząc do `test.test1` można zapisać 10 bajtów, a z opcja `2` można zapisać jedynie 5 bajtów. Należy o tym pamiętać używając tych flag.

Kompilator też ostrzeże nas o błędzie w przypadku takiego zapisu.

Opcja `fortify source` sprawia też ze ataki typu `format string` gdzie następuję użycie `%n` jest poprawne tylko tylko w `read-only memory` co efektywnie blokuje ten rodzaj ataków. Opcja ta nie pozwala też na pomijanie argumentów w `format string` - czyli stringi formatujące typu `printf("%2$s\n", 0, "Test");` są nie poprawne, gdyż pierwszy argument jest pominajny.




### 1.2 Wydajność

`Fortify source` może wpłynąć na wielkość kodu, który kompilujemy, ale jest to na pewno dość mały wpływ.

Opcja ta nie ma wpływu na performance, a nawet może go poprawiać.

### 1.3 Proof of concept


### 1.? Wnioski

Opcja `fortify-source` jest opcja, która powinna być włączona domyślnie. Jest to bardzo sprawny sposób minimalizacji ryzyka błędu w aplikacji. Równocześnie opcja ta nie ma dużego wpływu na performance.