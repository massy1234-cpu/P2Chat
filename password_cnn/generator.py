import csv
import math
import random
import string
from collections import Counter

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
PUNCT = "!@#$%^&*()-_=+[]{}|;:,.<>?"

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 4)

def load_rockyou_weak(filepath: str, target_count: int, allowed_chars: set) -> list[str]:
    """Estrae le prime N password uniche e pulite da RockYou."""
    weak_passwords = []
    seen = set()
    
    print(f"[*] Lettura da {filepath}...")
    with open(filepath, mode="r", encoding="latin-1", errors="ignore") as f:
        for line in f:
            pwd = line.strip()
            # Filtra stringhe vuote, duplicati e caratteri fuori dal vocabolario ASCII stampabile
            if not pwd or pwd in seen:
                continue
            if not set(pwd).issubset(allowed_chars):
                continue
            
            seen.add(pwd)
            weak_passwords.append(pwd)
            if len(weak_passwords) >= target_count:
                break
                
    if len(weak_passwords) < target_count:
        print(f"[!] Attenzione: trovate solo {len(weak_passwords)} password valide in RockYou.")
    return weak_passwords

def make_medium(vocab_samples: list[str]) -> str:
    """Crea una password media partendo da una base reale."""
    base = random.choice(vocab_samples).capitalize()
    mode = random.random()
    if mode < 0.5:
        # Parola reale + anno
        year = random.randint(1970, 2026)
        return f"{base}{year}"
    elif mode < 0.8:
        # Parola reale + 2-3 cifre casuali + simbolo base
        digits = "".join(random.choices(DIGITS, k=random.randint(2, 3)))
        sym = random.choice(["!", "?", "_", "."])
        return f"{base}{digits}{sym}"
    else:
        # Stringa alfanumerica generata casualmente (8-11 caratteri)
        return "".join(random.choices(LOWER + UPPER + DIGITS, k=random.randint(8, 11)))

def make_strong() -> str:
    """Genera password crittograficamente complesse (lunghezza 14-24)."""
    length = random.randint(14, 24)
    pwd = [
        random.choice(LOWER), random.choice(LOWER),
        random.choice(UPPER), random.choice(UPPER),
        random.choice(DIGITS), random.choice(DIGITS),
        random.choice(PUNCT), random.choice(PUNCT)
    ]
    all_chars = LOWER + UPPER + DIGITS + PUNCT
    pwd += random.choices(all_chars, k=length - len(pwd))
    random.shuffle(pwd)
    return "".join(pwd)

def build_dataset_with_rockyou(rockyou_path: str = "rockyou.txt", 
                               output_csv: str = "passwords_full.csv", 
                               total_samples: int = 100000):
    per_class = total_samples // 3
    extra = total_samples - (per_class * 3)

    # Insieme dei caratteri accettati dal tuo Tokenizer
    allowed_chars = set(string.ascii_letters + string.digits + string.punctuation)

    # 1. Carica la Classe 0 da RockYou
    weak_list = load_rockyou_weak(rockyou_path, per_class, allowed_chars)
    seen_all = set(weak_list)
    records = []

    for pwd in weak_list:
        records.append((pwd, len(pwd), calculate_entropy(pwd), 0))
    print(f"[+] Classe 0 completata: {len(records)} esempi da RockYou.")

    # 2. Genera la Classe 1 (usando parole da RockYou come base semantica realistica)
    # Seleziona parole lunghe almeno 4 caratteri da usare come radici
    word_bases = [w for w in weak_list if w.isalpha() and 4 <= len(w) <= 9]
    if not word_bases:
        word_bases = ["password", "computer", "juventus", "famiglia", "musica"]

    count_target_med = len(records) + per_class
    while len(records) < count_target_med:
        pwd = make_medium(word_bases)
        if pwd not in seen_all and set(pwd).issubset(allowed_chars):
            seen_all.add(pwd)
            records.append((pwd, len(pwd), calculate_entropy(pwd), 1))
    print(f"[+] Classe 1 completata: {per_class} esempi medi.")

    # 3. Genera la Classe 2 (Forte)
    count_target_strong = total_samples
    while len(records) < count_target_strong:
        pwd = make_strong()
        if pwd not in seen_all and set(pwd).issubset(allowed_chars):
            seen_all.add(pwd)
            records.append((pwd, len(pwd), calculate_entropy(pwd), 2))
    print(f"[+] Classe 2 completata: {per_class + extra} esempi forti.")

    # 4. Rimescolamento e scrittura CSV
    print("[*] Rimescolamento del dataset in corso...")
    random.shuffle(records)

    print(f"[*] Scrittura del file '{output_csv}'...")
    with open(output_csv, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["password", "length", "entropy", "strength"])
        writer.writerows(records)

    print(f"[SUCCESS] File '{output_csv}' generato correttamente con {len(records)} righe.")

if __name__ == "__main__":
    # Assicurati che il file rockyou.txt sia presente nella stessa cartella (o specifica il percorso completo)
    build_dataset_with_rockyou("rockyou.txt", "passwords_full.csv", 100000)
