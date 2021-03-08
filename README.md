# Projekt BSO

Tematem realizowanego projektu są techniki ochrony aplikacji natywnych oraz technik utrudniających ich ekspoitacje. 

Postaram się omówić plusy i minusy danych technik, sposoby ich obejścia oraz najpopularniejsze ataki na aplikacje natywne.

### Schemat plików

W każdych folderze nazwanym nazwą techniki znajdują się pliki następujące pliki:

* `vuln.c` - program, który bedzie exploitowany, kolejne `vuln_1.c` i tak dalej.
* `exploit.py` - exploit działający na programie, który został skompilowany bez techniki,kolejne `exploit_1.c` i tak dalej.
* `doc.md` - plik opisujący technikę oraz wykonanie eksploitu.