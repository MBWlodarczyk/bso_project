# 1. ASLR

### 1.1 Opis

ASLR (Address space layout randomization) - to technika polegająca na losowym umieszczeniu sekcji programu, aby uniemożliwić
skakanie do danych sekcji. Jest to dość duże utrudnienie w atakach binarnych. W dużej cześci ataków oznacza to po prostu zgadywanie danej wartości do skutku.

Główna róznica pomiedzy implementacją Linuxową i Windowsową jest to, że w Linuxie jest to opcja compile-time, a w Windowsie link-time.

W Linuxie ASLR jest implementowane w kernelu. Na linuxie ASLR ma wpływ na performance przez to, że binarki obsługujące ASLR muszą być kompilowane z PIE (Position Independent Executable), co prowadzi nawet do 25% gorszego performance'u na 32bit x86. 

Na Windowsie ASLR jest włączany poprzez linkowanie z opcja `/DYNAMICBASE`. Na windowsie wpływ na performance run-time jest raczej niewielki, ale ASLR może spowolnić ładowanie modułów.

### 1.2 Proof of Concept