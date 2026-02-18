# PCAP TCP Anomaly Detection

System detekcji anomalii i malware w ruchu sieciowym oparty na analizie sesji TCP z plików PCAP.

---

## Spis treści

1. [Cel projektu](#cel-projektu)
2. [Architektura systemu](#architektura-systemu)
3. [Dataset](#dataset)
4. [Pipeline przetwarzania danych](#pipeline-przetwarzania-danych)
5. [Strategia labelowania](#strategia-labelowania)
6. [Feature engineering](#feature-engineering)
7. [Analiza statystyczna](#analiza-statystyczna)
8. [Modele ML](#modele-ml)
9. [Wyniki](#wyniki)
10. [Uruchomienie](#uruchomienie)
11. [Struktura projektu](#struktura-projektu)
12. [Konkluzje i kierunki rozwoju](#konkluzje-i-kierunki-rozwoju)
13. [Spekulacje i pomysły warunkowe](#spekulacje-i-pomysly-warunkowe)

---

## Cel projektu

Projekt realizuje end-to-end pipeline ML do wykrywania złośliwego ruchu sieciowego na poziomie sesji TCP. Zamiast analizy sygnatur (jak tradycyjne IDS), system uczy się wzorców behawioralnych z surowych danych PCAP.

Kluczowe założenia projektowe:

- Dataset ma odzwierciedlać **realistyczny ruch sieciowy**, nie laboratoryjne proporcje
- Malware stanowi mały procent ruchu (realistyczny scenariusz)
- System musi być odporny na noise i niejednoznaczne sesje
- Architektura umożliwia przyszły retraining

---

## Architektura systemu

```
PCAP files
    |
    v
[TShark Parser]
    |
    v
Bronze Layer (raw packets, ~26M rows)
    |
    v
[SQL Transforms - bidirectional session grouping]
    |
    v
Silver Layer (265k sessions)
    |
    v
[Feature Engineering + Labeling]
    |
    v
Gold Layer (265k labeled flows, 18 features)
    |
    v
[Statistical Analysis]
    |
    v
[Feature Selection - 12 -> 7 features]
    |
    v
[Random Forest Classifier]
    |
    v
Model + Confidence Scoring
```

---

## Dataset

**Pliki PCAP:** 127 plików (42 oryginalne + 85 próbek malware z malware-traffic-analysis.net)

**Baza danych:** PostgreSQL, architektura Bronze/Silver/Gold

| Warstwa | Opis | Rozmiar |
|---------|------|---------|
| Bronze | Surowe pakiety | ~26M wierszy |
| Silver | Sesje bidirectionalne | 265,433 sesji |
| Gold | Feature vectors z labelami | 265,433 rekordów |

**Rozkład klas (Gold):**

| Label | Liczba | Procent |
|-------|--------|---------|
| suspicious | 131,764 | 49.6% |
| benign | 56,013 | 21.1% |
| background | 44,838 | 16.9% |
| malicious | 32,818 | 12.4% |

---

## Pipeline przetwarzania danych

### 1. Parsowanie PCAP (parse.py)

```python
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

# Kluczowe pola:
# - ip.src, ip.dst, tcp.srcport, tcp.dstport
# - tcp.flags, tcp.window_size, tcp.options.mss
# - ip.ttl, frame.len, frame.time_epoch
```

**Problem rozwiązany:** Windows path ze spacjami wymagał `shell=False` + lista argumentów zamiast string.

### 2. Grupowanie bidirectionalne sesji (SQL)

Kluczowa decyzja techniczna - sesje TCP wymagają grupowania **obu kierunków** w jedną sesję:

```sql
CASE
    WHEN src_ip < dst_ip THEN
        src_ip || ':' || src_port || '-' || dst_ip || ':' || dst_port
    ELSE
        dst_ip || ':' || dst_port || '-' || src_ip || ':' || src_port
END || '-' || protocol AS session_id
```

Bez tego SYN jest w sesji A, SYN-ACK w sesji B - żadna nie ma kompletnego handshake.

### 3. Ekstrakcja features (SQL → Gold)

18 features obliczanych per sesja, następnie zredukowanych do 7 (patrz Feature Engineering).

---

## Strategia labelowania

Zastosowano **operacyjne podejście 4-klasowe** zamiast sztucznie czystych danych:

| Label | Kryterium | Przykłady |
|-------|-----------|-----------|
| **malicious** | Oczywiste zagrożenia: port scan, C2-like, exfiltration | SYN flood, sessions z 1M+ pakietów |
| **suspicious** | Anomalie, szara strefa | Długie sesje bez handshake, high packet rate |
| **benign** | Typowy czysty ruch (strict criteria) | Complete handshake + proper close + reasonable duration |
| **background** | System noise | Single packets, bardzo krótkie incomplete |

**Kluczowa decyzja projektowa:** Surowe kryteria dla `benign` - nie każdy complete handshake = benign. Efekt: ~50% ruchu trafia do `suspicious` (realistyczne - w SOC większość alertów to "investigate").

### Dlaczego nie ma klasy "incomplete_session" jako głównej?

`incomplete_session` to **stan połączenia**, nie typ ruchu. Może być:
- Failed legit connection (benign)
- SYN scan (malicious)  
- Malware C2 reconnect loop (malicious)
- Firewall drop (background)

Dlatego traktowana jako feature pomocniczy, nie główny label.

---

## Feature engineering

### Pełny zestaw (18 features):

| Feature | Opis | Typ |
|---------|------|-----|
| log_packet_count | log(packet_count + 1) | numeric |
| duration | czas trwania sesji [s] | numeric |
| packets_per_second | tempo pakietów | numeric |
| bytes_per_second | przepustowość | numeric |
| avg_packet_size | średni rozmiar pakietu | numeric |
| syn_ratio | SYN / total packets | ratio |
| ack_ratio | ACK / total packets | ratio |
| rst_ratio | RST / total packets | ratio |
| fin_ratio | FIN / total packets | ratio |
| handshake_complete | czy TCP handshake kompletny | binary |
| proper_close | czy FIN/RST close | binary |
| ttl_mean | średnie TTL | numeric |
| ttl_std | odchylenie TTL | numeric |
| window_mean | średni TCP window | numeric |
| window_std | odchylenie TCP window | numeric |
| mss_present | czy MSS option obecny | binary |
| sack_present | czy SACK option obecny | binary |
| is_burst | czy wysokie PPS (burst traffic) | binary |

### Analiza korelacji → Redukcja do 7 features

Analiza wykazała 13 par z korelacją r > 0.8 (redundancja). Po redukcji metodą eta² (Kruskal-Wallis effect size):

**Usunięte (trivially separable lub redundant):**
- `syn_ratio`, `rst_ratio`, `fin_ratio` - bezpośrednio kodują definicję labelów
- `ack_ratio`, `sack_present` - r=0.97 wzajemnie
- `handshake_complete`, `mss_present`, `proper_close` - r>0.96 cluster
- `packets_per_second`, `bytes_per_second` - r=0.983
- `avg_packet_size`, `window_mean` - redundant

**Finalne 7 features (True Learning Set):**

| Feature | eta² | Rola |
|---------|------|------|
| log_packet_count | 0.573 | Volume indicator |
| window_std | 0.478 | TCP behavior proxy |
| duration | 0.463 | Temporal pattern |
| bytes_per_second | 0.490 | Transfer rate |
| ttl_mean | 0.318 | Network fingerprint |
| ttl_std | 0.347 | Network variance |
| is_burst | 0.516 | Temporal burst pattern |

**Dlaczego usunięcie TCP ratios jest kluczowe:**

Model z pełnym zestawem osiągał 99.98% accuracy - ale to "glorified lookup table", nie uczenie maszynowe. TCP flag ratios bezpośrednio kodują logikę labelowania. Po usunięciu accuracy spada do 88%, co oznacza że model **naprawdę się uczy wzorców**, nie memoryzuje definicji.

---

## Analiza statystyczna

Przeprowadzona w `python/statistical_analysis.py`:

### Kluczowe wyniki:

**Normalność (Shapiro-Wilk):** 0/18 features ma rozkład normalny → modele linearne wykluczone.

**Outliers (IQR method):**
- log_packet_count: 43% outliers
- bytes_per_second: 20% outliers
- duration: 18% outliers

Outliers to nie błędy - to sygnatury malware (C2 beaconing = ekstremalna długość, DDoS = ekstremalny volume).

**PCA:** 9/12 komponentów = 95% variance → większość features unikalna po redukcji.

**Class separability (Kruskal-Wallis):** Wszystkie 12 features mają eta² > 0.14 (large effect). Top: ack_ratio (eta²=0.758).

### Wybór modelu (Decision Matrix):

| Property | Value | Implication |
|----------|-------|-------------|
| Linearity | NON-LINEAR (0/18 normal) | Wyklucza LR, Naive Bayes |
| Outliers | HIGH (43%) | Wyklucza KNN, SVM |
| Separability | EXCELLENT (eta²=0.76) | RF wystarczy, XGB overkill |
| Sample size | 265k | Wystarczy dla złożonych modeli |

---

## Modele ML

### Eksperyment 1: Full features (Baseline)

```
Test Accuracy: 99.98%
Problem: Circular reasoning - features = label definitions
Wniosek: Model jest encyklopedią reguł, nie klasyfikatorem
```

### Eksperyment 2: True Learning (7 features)

```
Random Forest: Test F1 = 88.29%, gap = 0.10%
XGBoost:       Test F1 = 84.05%, gap = 0.96%
```

### Final Model: Random Forest

```python
RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    min_samples_split=20,
    min_samples_leaf=10,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1
)
```

**Dlaczego Random Forest wygrywa z XGBoost:**

RF jest lepszy gdy:
- Outliers są ekstremalne (43% danych) - bagging "rozmywa" je przez sampling
- Sygnał malware jest lokalny i fragmentaryczny, nie globalnie ciągły
- Redundancja features jest wysoka - feature bagging naturalne ignoruje

XGBoost traci, bo boosting sequential może overfitować na outliers.

---

## Wyniki

### Per-class performance (Random Forest, True Learning):

| Class | Precision | Recall | F1 |
|-------|-----------|--------|----|
| background | 1.00 | 1.00 | 1.00 |
| benign | 0.97 | 1.00 | 0.98 |
| suspicious | 1.00 | 0.76 | 0.86 |
| **malicious** | **0.52** | **1.00** | **0.69** |

**Interpretacja wyników malicious:**
- Recall = 1.00 oznacza że model **nie przeoczy żadnego malware** (zero false negatives)
- Precision = 0.52 oznacza że połowa alertów wymaga weryfikacji
- To jest akceptowalny trade-off dla IDS: lepiej mieć false alarm niż przeoczyć atak

### Porównanie modeli:

| Metric | RF (full) | RF (7 feat) | XGB (7 feat) |
|--------|-----------|-------------|--------------|
| Test Accuracy | 99.98% | 88.0% | 87.7% |
| Test F1 macro | 99.98% | 88.3% | 84.1% |
| Malicious F1 | 1.00* | 0.69 | 0.49 |
| Overfitting gap | 0.01% | 0.10% | 0.96% |
| Training time | 4s | 7s | 13s |

*Wynik iluzoryczny - circular reasoning

---

## Uruchomienie

### Wymagania

```
Python 3.10+
PostgreSQL 14+
Wireshark/TShark
```

### Instalacja

```bash
cd PCAP-TCP-Anomaly-Detection
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install pandas numpy scikit-learn xgboost matplotlib seaborn scipy
```

### Pipeline

```bash
# 1. Parsuj PCAP do Bronze
python python/parse.py

# 2. SQL transforms (Bronze -> Silver -> Gold)
# Wykonaj sql/transforms.sql w DataGrip/psql

# 3. Export Gold do CSV
# COPY (SELECT * FROM gold) TO 'data/gold/gold.csv' DELIMITER ',' CSV HEADER;

# 4. Analiza statystyczna
python python/statistical_analysis.py

# 5. Trening modeli (porównanie)
python python/train_models.py

# 6. Final model (True Learning)
python python/train_true_learning.py
```

---

## Struktura projektu

```
PCAP-TCP-Anomaly-Detection/
├── data/
│   ├── bronze/          # Surowe pakiety CSV
│   ├── silver/          # Sesje CSV (opcjonalnie)
│   └── gold/
│       ├── gold.csv          # Pełny dataset (18 features)
│       └── gold_reduced.csv  # Zredukowany (12 features)
├── python/
│   ├── parse.py              # TShark PCAP parser
│   ├── statistical_analysis.py  # Analiza statystyczna
│   ├── train_models.py          # RF vs XGBoost comparison
│   └── train_true_learning.py   # Final 7-feature model
├── sql/
│   └── transforms.sql        # Bronze->Silver->Gold transformations
├── experiments/
│   ├── rf_results.json
│   ├── xgb_results.json
│   └── confusion_matrices.png
├── analysis/
│   ├── 01_descriptive_statistics.csv
│   ├── 02_correlation_heatmap.png
│   ├── 03_class_separability.csv
│   ├── 04_normality_tests.csv
│   ├── 05_outlier_analysis.csv
│   └── 06_pca_analysis.png
├── models/
│   └── random_forest_final.pkl
└── README.md
```

---

## Konkluzje i kierunki rozwoju

### Konkluzja główna

Random Forest z 7 behawioralnymi features osiąga 88% accuracy i recall=1.00 dla malicious class. Kluczowe odkrycie: sygnał malware w danych jest **lokalny i fragmentaryczny** (wiele niezależnych wskazówek), co faworyzuje RF nad XGBoost.

### Decyzja RF vs XGBoost zależy od scenariusza:

**Jeśli brak aktywnego retrainingu:** Random Forest jest bezpieczniejszym wyborem. Uczy się wielu niezależnych heurystyk odpornych na concept drift.

**Jeśli regularny retraining (pipeline SOC):** XGBoost ma większy potencjał. Lepiej adaptuje się do nowych wzorców przy dostępności świeżych labeled samples.

Nie jesteśmy w stanie przewidzieć jak malware będzie wyglądać w przyszłości. Skuteczność długoterminowa zależy bardziej od procesu aktualizacji danych niż od wyboru algorytmu.

### Kierunki rozwoju

- Detekcja concept drift (monitoring feature importance w czasie)
- Semi-supervised learning dla nieoznakowanego ruchu
- Anomaly detection jako warstwa pomocnicza
- Web interface: upload PCAP → wynik z confidence score
- Continuous learning pipeline (zbieranie PCAP → walidacja → retraining)

---

## Spekulacje i pomysly warunkowe

Poniższe idee były dyskutowane podczas projektu. Nie zostały wdrożone, ale mogą być wartościowe w określonych scenariuszach.

### Memory Augmentation (RAG dla ML)

Pomysł: system przechowuje historię przypadków i dodaje similarity features do klasyfikacji.

Przykład: "ta sesja jest 87% podobna do 3 znanych przypadków C2 z 2024" → dodatkowy feature.

Warunek przydatności: dostęp do threat intelligence feed z labeled samples historycznych.

Ważne: RAG zmienia warstwę informacji, nie bias modelu. RF może korzystać z memory równie dobrze jak XGBoost - nie daje to XGBoost magicznej przewagi.

### Ensemble RF + XGBoost (Stacking)

Pomysł: RF generuje stabilne predykcje jako features dla XGBoost drugiego poziomu.

Kiedy ma sens: gdy oba modele robią różne błędy (komplementarne). Wymaga analizy confusion matrix obu modeli przed implementacją.

Ryzyko: trudniejsze wyjaśnienie w pracy naukowej, możliwy leakage.

### System if-else heurystyk jako warstwa nad ML

Pomysł: deterministyczne reguły override'ujące predykcję modelu.

Przykłady zastosowań:
- Whitelist znanych IP (zawsze benign)
- Threshold override: jeśli packet_count > 1,000,000 → zawsze malicious, bez pytania modelu
- Krytyczne sygnały (np. znany C2 domain w DNS)

Warunek przydatności: środowisko produkcyjne z dobrze zdefiniowanymi regułami bezpieczeństwa.

### Dynamiczne mapowanie labeli

Pomysł: przechowywanie granularnych labeli (10+ klas) z mapowaniem do uproszczonych podczas treningu.

```python
# Granularne (w bazie):
label_map_binary = {
    'normal_long': 'benign', 'scan': 'malicious',
    'suspicious_long_session': 'malicious', ...
}

# Elastyczność eksperymentów bez ponownego labelowania danych
```

### Confidence-based Decision Layer

Pomysł: zamiast binary classification, system zwraca risk score z progami decyzyjnymi.

```python
thresholds = {
    'very_high': 0.90,  # BLOCK IMMEDIATELY
    'high': 0.75,       # BLOCK
    'medium': 0.50,     # INVESTIGATE
    'low': 0.30,        # MONITOR
    'very_low': 0.00    # ALLOW
}
```

To podejście (risk scoring engine zamiast klasyfikatora) jest standardem w nowoczesnych systemach SOC.

### Continuous Learning Pipeline

Docelowa architektura dla środowiska produkcyjnego:

```
Nowe PCAP
    |
    v
[Automated Feature Extraction]
    |
    v
[Model Prediction + Confidence]
    |
    v
[Analyst Review (uncertain cases)]
    |
    v
[Labeled Dataset]
    |
    v
[Periodic Retraining]
    |
    v
[Drift Monitoring]
```

Kluczowe: model nie "pamięta" poprzednich treningów. Historia = dataset, nie cache decyzji. Zapobiega to bias reinforcement i ułatwia kontrolę nad overfittingiem.

---

*Projekt realizowany jako praca badawcza z zakresu network security ML.*
*Polsko-Japońska Akademia Technik Komputerowych, 2026.*
