# PCAP-TCP-Anomaly-Detection
# Analiza Ruchu Sieciowego - Dataset W32/Sdbot PCAP

## Przegląd Datasetu

Nazwa pliku: toolsmith.pcap
Źródło: https://holisticinfosec.io/toolsmith/files/nov2k6/toolsmith.pcap
Malware: W32/Sdbot (bot/trojan oparty na IRC)
Liczba pakietów: 392
Czas trwania: 10.868 sekund
Średnia częstotliwość: 36.1 pakietów/sekundę
Rozmiar: 79,179 bajtów

---

## Profil Ruchu

Przechwycenie pokazuje zainfekowaną maszynę pod adresem 192.168.1.1 przeprowadzającą automatyczne skanowanie przeciwko 9 zewnętrznym celom. Ruch to 95.4% TCP, 4.6% DNS. Główna aktywność to skanowanie HTTP na porcie 80 z jednym połączeniem na port 5050. Wszystkie żądania HTTP zwracają odpowiedź 404 Not Found, co wskazuje na nieudane próby eksploatacji.

Geograficzne rozproszenie obejmuje cele w Japonii, Europie i regionie Azji i Pacyfiku. Timing pokazuje zautomatyzowane zachowanie z konsystentnymi interwałami poniżej sekundy. Całe przechwycenie reprezentuje około 10.8 sekundy agresywnej aktywności skanowania.

---

## Główne Wykryte Anomalie

**Skanowanie Portów**
Pojedyncze źródło 192.168.1.1 skontaktowało się z 9 unikalnymi zewnętrznymi adresami IP w ciągu 10.8 sekund. To oznacza jeden nowy cel co 1.2 sekundy, co znacznie przekracza wzorce interakcji ludzkiej.

**Niekompletne Handshaki**
35 połączeń TCP pokazuje pakiety SYN bez prawidłowego zakończenia przez ACK. To stanowi około 35% wskaźnik niepowodzeń w porównaniu do normalnych sieci poniżej 5%. Wzorzec wskazuje na skanowanie SYN zamiast legalnej komunikacji.

**Próby Eksploatacji HTTP**
68 pakietów HTTP celuje w podejrzane ścieżki włączając /cgi-bin/proxy.c i /mute/c/prxjdg.c. Wszystkie żądania otrzymują odpowiedzi 404. Wzorzec pasuje do znanego zachowania propagacji Sdbota.

**Niestandardowy Port**
Połączenie do 84.244.1.30 na porcie 5050 związane z aktywnością backdoor/trojan. Brak legalnego uzasadnienia biznesowego dla użycia tego portu.

**Problemy DNS**
Wykryto retransmisję dla zapytania do cgi14.plala.or.jp. Ruch DNS stanowi tylko 4.6% przechwycenia pomimo wielu celów, co sugeruje bezpośrednie adresowanie IP lub cache'owane wyniki.

---

## Analiza na Poziomie TCP dla Wykrywania Anomalii

### Analiza TTL (Time To Live)

**Dlaczego TTL jest Ważny:**
TTL wskazuje liczbę hopów, które pakiet może przejść przez sieć. Normalne wartości dla systemów lokalnych to 64 (Linux) lub 128 (Windows). Znacząco niższe wartości mogą wskazywać pakiety z odległych sieci lub próby spoofingu.

**Anomalie TTL:**
- Nieoczekiwane zmiany TTL od tego samego źródła mogą wskazywać IP spoofing
- TTL poniżej 30 dla sieci lokalnej sugeruje routing przez wiele hopów lub manipulację
- Różne wartości TTL w ramach jednej sesji TCP są podejrzane

**Zastosowanie w Detekcji:**
Monitorowanie TTL pomaga wykryć rozproszone ataki, gdzie pakiety pochodzą z różnych źródeł mimo pokazywania tego samego źródłowego IP. Również wykrywa próby fingerprinting systemu operacyjnego, gdzie atakujący zmieniają TTL aby imitować różne systemy.

**W Tym PCAP:**
Powinniśmy sprawdzić czy 192.168.1.1 utrzymuje spójny TTL we wszystkich pakietach. Zmiany TTL wskazywałyby na spoofing lub użycie proxy. Docelowe adresy IP będą miały różne TTL w zależności od odległości geograficznej.

### Sekwencje Numerów ACK

**Dlaczego Numery ACK są Ważne:**
Numer ACK w TCP wskazuje następny oczekiwany bajt. Normalna komunikacja pokazuje spójną sekwencję ACK odpowiadającą numerom SEQ. Anomalie w ACK wskazują problemy lub ataki.

**Anomalie ACK:**
- Numery ACK które nie odpowiadają wysłanym numerom SEQ mogą wskazywać ataki typu injection
- Duplikaty ACK mogą sygnalizować utratę pakietów lub ataki retransmisji
- Brak ACK po SYN-ACK wskazuje niekompletny handshake (widoczne w tym PCAP)

**Zastosowanie w Detekcji:**
Analiza sekwencji ACK wykrywa przechwytywanie sesji TCP, gdzie atakujący wstrzykują pakiety z nieprawidłowymi numerami ACK. Również pomaga zidentyfikować ataki reset i manipulację połączeniami.

**W Tym PCAP:**
35 sesji pokazuje SYN i SYN-ACK ale brakuje końcowego ACK. To oznacza że zainfekowana maszyna inicjuje połączenie, cel odpowiada, ale bot nie wysyła ACK aby zakończyć handshake. Ten wzorzec to klasyczne skanowanie SYN.

### Rozmiar Okna TCP

**Dlaczego Rozmiar Okna jest Ważny:**
Rozmiar okna kontroluje kontrolę przepływu w TCP, wskazując ile danych odbiorca może przyjąć. Normalne wartości to 65535 bajtów (64KB) lub wielokrotności z window scaling.

**Anomalie Okna:**
- Rozmiar okna równy 0 może wskazywać próbę DoS (wyczerpanie okna)
- Bardzo małe wartości (np. 1-100 bajtów) są nietypowe dla normalnej komunikacji
- Brak window scaling przy dużych transferach jest podejrzany

**Zastosowanie w Detekcji:**
Manipulacja oknem jest używana w niektórych atakach aby spowolnić lub zatrzymać komunikację. Monitorowanie wzorców rozmiaru okna pomaga wykryć ataki DoS o niskiej częstotliwości.

**W Tym PCAP:**
Wartości rozmiaru okna powinny być konsystentne dla 192.168.1.1. Jeśli bot używa małych wartości, może to wskazywać próbę minimalizacji własnego zużycia zasobów podczas skanowania.

### Opcje TCP - Window Scale

**Dlaczego Window Scale jest Ważny:**
Opcja window scale (TCP option kind 3) pozwala na okna większe niż 65535 bajtów poprzez zastosowanie współczynnika przesunięcia. Obecność tej opcji wskazuje że host wspiera połączenia o wysokiej przepustowości.

**Anomalie Window Scale:**
- Brak window scale w nowoczesnych systemach jest nietypowy
- Niespójne użycie tej opcji w różnych połączeniach od tego samego hosta może wskazywać OS spoofing
- Nieprawidłowe wartości scale (powyżej 14) są błędem lub próbą manipulacji

**Zastosowanie w Detekcji:**
Window scale pomaga w fingerprinting systemu operacyjnego. Różne systemy używają różnych domyślnych współczynników scale. Linux często używa scale 7, Windows 8. Brak tej opcji może wskazywać legacy system lub narzędzie skanujące.

**W Tym PCAP:**
Sprawdzenie czy 192.168.1.1 używa window scale konsystentnie pomoże określić czy to prawdziwy system operacyjny czy skrypt/narzędzie generujące pakiety.

### Opcje TCP - SACK Permitted

**Dlaczego SACK jest Ważny:**
Selective Acknowledgment (SACK, option kind 4) pozwala na potwierdzenie nieciągłych bloków danych, poprawiając wydajność przy utracie pakietów. SACK permitted pojawia się w pakietach SYN jeśli host wspiera tę funkcję.

**Anomalie SACK:**
- Nowoczesne systemy prawie zawsze deklarują SACK permitted
- Brak SACK może wskazywać stary system lub narzędzie skanujące które nie implementuje pełnego stosu TCP
- Niespójne użycie SACK od tego samego hosta jest podejrzane

**Zastosowanie w Detekcji:**
Obecność lub brak SACK permitted jest częścią fingerprinting systemu operacyjnego. Ataki często pomijają opcjonalne funkcje TCP aby uprościć implementację. Monitorowanie wzorców SACK pomaga wykryć zautomatyzowane narzędzia versus prawdziwe systemy.

**W Tym PCAP:**
Jeśli 192.168.1.1 nie deklaruje SACK permitted w pakietach SYN, sugeruje to że bot używa uproszczonej implementacji TCP. Prawdziwy system Windows/Linux deklarowałby wsparcie SACK.

### Opcje TCP - Maximum Segment Size (MSS)

**Dlaczego MSS jest Ważny:**
MSS (option kind 2) deklaruje największy segment który host może przyjąć, typowo 1460 bajtów dla Ethernet (1500 MTU minus 40 bajtów nagłówków IP/TCP). MSS zawsze pojawia się w pakietach SYN.

**Anomalie MSS:**
- Bardzo mały MSS (np. poniżej 536) jest nietypowy dla nowoczesnych sieci
- Bardzo duży MSS (powyżej 1460 bez jumbo frames) może wskazywać manipulację
- Brak opcji MSS w pakiecie SYN jest błędem protokołu

**Zastosowanie w Detekcji:**
Wartości MSS pomagają wykryć narzędzia do tworzenia pakietów które używają niestandardowych wartości. Również wskazują charakterystyki ścieżki sieciowej - MSS 1460 sugeruje standardowy Ethernet, inne wartości mogą wskazywać VPN, tunelowanie lub spoofing.

**W Tym PCAP:**
Sprawdzenie MSS w pakietach SYN od 192.168.1.1 pomoże określić czy bot używa realistycznych parametrów sieciowych czy arbitralnych wartości. Cele będą miały różne MSS w zależności od ich konfiguracji sieciowej.

### Opcje TCP - Timestamps

**Dlaczego Timestampy są Ważne:**
Opcja TCP timestamps (kind 8) zawiera wartość timestamp i echo reply używane do pomiaru RTT i PAWS (Protection Against Wrapped Sequences). Nowoczesne systemy prawie zawsze używają timestamps.

**Anomalie Timestamps:**
- Brak timestamps w nowoczesnym systemie jest nietypowy
- Wartości timestamp które nie rosną monotonicznie wskazują manipulację
- Niespójne użycie timestamp od tego samego hosta jest podejrzane

**Zastosowanie w Detekcji:**
Analiza timestamp wykrywa ataki powtórzenia pakietów gdzie stare pakiety są retransmitowane. Również pomaga w analizie timingu aby wykryć zautomatyzowane versus ludzkie zachowanie. Timestamp echo replies pomagają wykryć przechwytywanie sesji.

**W Tym PCAP:**
Jeśli 192.168.1.1 używa timestamps, wartości powinny rosnąć konsystentnie. Brak timestamps sugeruje uproszczoną implementację bota. Analiza przyrostów timestamp może pokazać regularność timingu charakterystyczną dla zautomatyzowanego skanowania.

---

## Inżynieria Cech dla Detekcji ML

### Główne Cechy z Analizy TCP

**Cechy oparte na TTL:**
- Wynik spójności TTL: odchylenie standardowe wartości TTL od źródłowego IP
- Korelacja geograficzna TTL: czy TTL odpowiada oczekiwanej liczbie hopów do celu
- Wskaźnik manipulacji TTL: czy TTL zmienia się w sposób niespójny z routingiem

**Cechy oparte na ACK:**
- Wskaźnik niekompletnych handshake'ów: procent sesji bez końcowego ACK
- Ważność sekwencji ACK: czy numery ACK odpowiadają numerom SEQ
- Częstotliwość duplikatów ACK: częstotliwość duplikatów potwierdzeń wskazujących retransmisje

**Cechy oparte na Oknie:**
- Wariancja rozmiaru okna: spójność rozmiaru okna w sesjach
- Obecność window scale: czy używa nowoczesnych funkcji TCP
- Częstotliwość zerowego okna: wskaźnik ogłoszeń zerowego okna

**Odcisk palca Opcji TCP:**
- Spójność opcji: czy ten sam host używa tych samych opcji w różnych połączeniach
- Wynik nowoczesnych funkcji: obecność SACK, timestamps, window scale
- Rozkład wartości MSS: czy MSS jest realistyczny dla typu sieci

**Cechy czasowe:**
- Regularność międzypakietowa: wariancja timingu między pakietami
- Częstotliwość inicjowania połączeń: częstotliwość nowych połączeń na sekundę
- Rozkład czasu trwania sesji: czy połączenia są nienaturalnie krótkie

**Cechy na poziomie sesji:**
- Wskaźnik ukończenia handshake
- Częstotliwość retransmisji
- Wskaźnik pakietów reset
- Wynik różnorodności geograficznej

---

## Strategia Detekcji

### Warstwa 1: Walidacja Protokołu TCP

Pierwsza warstwa detekcji sprawdza czy nagłówki TCP są poprawne i spójne. Błędy na tym poziomie wskazują tworzenie pakietów lub uszkodzone implementacje.

Walidacje:
- Czy pakiety SYN zawierają opcję MSS
- Czy numery sekwencji są prawidłowo zainicjalizowane
- Czy numery ACK odpowiadają poprzednim numerom SEQ
- Czy rozmiar okna jest niezerowy dla ustanowionych połączeń
- Czy opcje TCP są syntaktycznie poprawne

Naruszenia na tym poziomie mają wysoką pewność jako wskaźniki złośliwej aktywności.

### Warstwa 2: Analiza Behawioralna

Druga warstwa analizuje wzorce w legalnych sesjach TCP aby wykryć nietypowe zachowanie.

Analiza:
- Wskaźnik niekompletnych handshake'ów przekracza próg 5%
- Częstotliwość połączeń przekracza 10 połączeń/sekundę
- Wszystkie żądania HTTP zwracają 404 (nieudana eksploatacja)
- Różnorodność geograficzna przekracza 3 kraje w krótkim czasie
- Czas trwania sesji jest konsystentnie poniżej 10 sekund

Kombinacja wielu wskaźników behawioralnych zwiększa pewność detekcji.

### Warstwa 3: Fingerprinting TCP

Trzecia warstwa używa opcji i parametrów TCP aby stworzyć odcisk palca źródła i wykryć niespójności.

Fingerprinting:
- Porównanie profilu opcji TCP ze znanymi sygnaturami systemów operacyjnych
- Wykrywanie zmian w odcisku palca od tego samego źródłowego IP
- Identyfikacja uproszczonych implementacji TCP charakterystycznych dla narzędzi skanujących
- Korelacja wartości TTL z oczekiwanymi domyślnymi wartościami systemu operacyjnego

Niezgodności między deklarowanym systemem operacyjnym (np. w HTTP User-Agent) a odciskiem palca TCP wskazują oszustwo.

### Warstwa 4: Ocena Anomalii przez Machine Learning

Czwarta warstwa używa modelu ML wytrenowanego na normalnym ruchu aby ocenić odchylenia.

Model przyjmuje wszystkie wyodrębnione cechy:
- Metryki spójności TTL
- Wyniki analizy ACK/SEQ
- Wzorce rozmiaru okna
- Odcisk palca opcji TCP
- Charakterystyki czasowe
- Wskaźniki ukończenia sesji
- Wzorce geograficzne

Wyjście modelu: wynik anomalii od -1 (ekstremalny outlier) do 1 (normalny). Próg -0.5 wyzwala śledztwo, -0.7 wyzwala blokowanie.

---

## Oczekiwane Wyniki dla tego PCAP

### Detekcja Oparta na Regułach

Źródło 192.168.1.1 powinno wywołać:
- Wykrycie niekompletnego handshake (35% wskaźnik niepowodzeń)
- Wysoka częstotliwość połączeń (36.1 pps utrzymane)
- Wykrycie skanowania portów (9 celów w 10.8 sekund)
- Anomalia geograficzna (skontaktowane 5+ krajów)
- Wzorzec eksploatacji HTTP (100% odpowiedzi 404)

### Analiza Protokołu TCP

Oczekiwane ustalenia:
- Wartości TTL powinny być spójne dla 192.168.1.1 jeśli to prawdziwy lokalny host
- Sekwencje ACK pokażą 35 przypadków brakujących końcowych pakietów ACK
- Rozmiary okna prawdopodobnie będą małe/standardowe jeśli bot minimalizuje zasoby
- Opcje TCP prawdopodobnie będą uproszczone (brak SACK/timestamps) jeśli to narzędzie skanujące
- Wartości MSS powinny być standardowe 1460 jeśli bot nie manipuluje tym parametrem

### Prognoza Modelu ML

Wektor cech dla 192.168.1.1:
- Spójność TTL: Wysoka (jeśli lokalny) lub Zmienna (jeśli spoofowany/proxy)
- Wskaźnik niekompletnych handshake'ów: 0.35 (35%)
- Częstotliwość połączeń: 36.1 połączeń/sekundę
- Średni czas trwania sesji: 3.24 sekundy
- Różnorodność geograficzna: 5+ krajów
- Wskaźnik niepowodzeń HTTP: 1.0 (100%)
- Wynik opcji TCP: Niski (jeśli uproszczony stos)
- Regularność timingu: Wysoka (zautomatyzowany wzorzec)

Oczekiwany wynik anomalii: -0.78 (silny outlier)
Klasyfikacja: Złośliwe z pewnością 95%+

---

## Priorytety Implementacji

### Krytyczne Pola TCP do Wyodrębnienia

Z każdego pakietu:
- IP TTL
- Numer sekwencji TCP
- Numer potwierdzenia TCP
- Rozmiar okna TCP
- Flagi TCP (SYN, ACK, FIN, RST)
- Opcje TCP (parsowanie MSS, SACK permitted, window scale, timestamps)

Z każdej sesji:
- Status ukończenia handshake (3-way zakończony?)
- Ważność sekwencji ACK (czy numery się zgadzają?)
- Wariancja rozmiaru okna w całej sesji
- Liczba retransmisji
- Spójność opcji w pakietach

### Obliczanie Cech

Agregacja per źródłowy IP:
- Odchylenie standardowe TTL
- Procent niekompletnych handshake'ów
- Średnia liczba pakietów na sekundę
- Liczba unikalnych celów
- Statystyki czasu trwania sesji
- Hash odcisku palca opcji TCP
- Wynik różnorodności geograficznej

### Progi Detekcji

Oparte na tym PCAP i normalnym baseline:
- Wskaźnik niekompletnych handshake'ów > 0.10 (10%) = Alert średni
- Wskaźnik niekompletnych handshake'ów > 0.25 (25%) = Alert wysoki
- Częstotliwość połączeń > 10/sek utrzymana = Alert wysoki
- Unikalne cele > 5 w 60 sekund = Alert średni
- Różnorodność geograficzna > 3 kraje w 60 sekund = Alert średni
- Kombinacja 3+ wskaźników = Alert krytyczny

---

## Rozważania dotyczące Schematu SQL

### Warstwa Bronze - Surowe Pakiety

Minimalnie przechowywać:
- packet_id, timestamp, src_ip, dst_ip, src_port, dst_port
- protocol, tcp_flags
- ttl, tcp_seq, tcp_ack, tcp_window
- tcp_options_raw (binarny blob dla parsowania)
- packet_length

### Warstwa Silver - Sesje

Agregować do:
- session_id, src_ip, dst_ip, src_port, dst_port
- start_time, end_time, duration
- packet_count, byte_count
- syn_count, ack_count, fin_count, rst_count
- handshake_complete (boolean)
- ttl_values (tablica lub statystyki)
- ack_sequence_valid (boolean)
- avg_window_size, window_size_variance
- tcp_options_fingerprint (parsowana struktura)

### Warstwa Silver - Opcje TCP

Oddzielna tabela dla parsowanych opcji:
- session_id (klucz obcy)
- mss_value
- window_scale_value
- sack_permitted (boolean)
- timestamps_present (boolean)
- timestamp_values (dla analizy timingu)

### Warstwa Gold - Anomalie

Wyniki detekcji:
- anomaly_id, session_id
- detection_method (rule_based, ml_model)
- anomaly_type (port_scan, incomplete_handshake, itd)
- ttl_anomaly_score
- ack_anomaly_score
- tcp_options_anomaly_score
- combined_confidence_score
- reason_text

---

## Podsumowanie

Analiza tego PCAP pokazuje że cechy na poziomie TCP są krytyczne dla wykrywania anomalii. Spójność TTL, walidacja sekwencji ACK, wzorce rozmiaru okna i fingerprinting opcji TCP dostarczają bogatego sygnału dla rozróżniania złośliwego od legalnego ruchu.

Niekompletne handshake'y (35% w tym PCAP) są najsilniejszym wskaźnikiem aktywności skanowania. Kombinacja z analizą timingu (36.1 pps), różnorodnością geograficzną (9 adresów IP w 5+ krajach) i wzorcami niepowodzeń HTTP (100% 404) daje detekcję o wysokiej pewności.

Implementacja powinna priorytetyzować wyodrębnianie pól nagłówka TCP i opcji, obliczanie statystyk na poziomie sesji i korelację wielu wskaźników dla solidnej detekcji z niską częstotliwością fałszywych pozytywów.

Dataset jest doskonały do treningu i testowania pipeline'u detekcji z wyraźną prawdą podstawową (192.168.1.1 = złośliwe, cele = ofiary).

---

Koniec Analizy
