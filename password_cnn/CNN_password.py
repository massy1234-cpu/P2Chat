# in this file i will implement a neural network for classify password
# i will implement this into P2Chat

import torch
import torch.nn as nn
from torch.nn.utils.rnn import pad_sequence
import string
import math
from collections import Counter
import pandas as pd
from torch.utils.data import Dataset
from torch.utils.data import DataLoader, random_split

class PasswordDataset(Dataset):
    def __init__(self, csv_path: str, tokenizer):
        df = pd.read_csv(csv_path).dropna(subset=["password", "length", "entropy", "strength"])

        # extract columns as lists
        self.passwords = df["password"].astype(str).tolist()
        self.lengths = df["length"].astype(float).tolist()
        self.entropies = df["entropy"].astype(float).tolist()
        self.labels = df["strength"].astype(int).tolist()

        self.tokenizer = tokenizer

    def __len__(self):
        return len(self.passwords)

    def __getitem__(self, index):
        tokens = self.tokenizer.encode(self.passwords[index])
        label = self.labels[index]

        norm_length = min(self.lengths[index] / 32.0, 1.0)
        norm_entropy = min(self.entropies[index] / 5.0, 1.0)

        numeric_features = [norm_length, norm_entropy]

        return tokens, label, numeric_features


class Tokenizer:
    def __init__(self):
        self.pad = "<PAD>"
        self.unk = "<UNK>"
        d = [self.pad, self.unk] + list(string.ascii_letters + string.digits + string.punctuation)
        self.char2idx = {char: idx for idx, char in enumerate(d)}
        self.idx2char = {idx: char for idx, char in enumerate(d)}
        self.vocab_size = len(self.char2idx)

    # convert the input into ID
    def encode(self, text: str) -> list[int]:
        unk_id = self.char2idx[self.unk]
        t = []

        if not isinstance(text, str):
            raise TypeError(f"Attesa stringa, ricevuto {type(text).__name__}")
        for char in text:
            idx = self.char2idx.get(char, unk_id)
            t.append(idx)
        return t


def collate_fn(batch):
    # unzip and get the max dimension for the batch 
    token, label, features = zip(*batch)
    lengths = [len(t) for t in token]
    max_len = max(lengths)

    # pytorch need a perfect rectangle for execute matrix operations
    matrix_initial = torch.zeros(len(token), max_len, dtype=torch.long)
    mask = torch.zeros(len(token), max_len, dtype=torch.bool)

    for i, t in enumerate(token):
        matrix_initial[i, :len(t)] = torch.tensor(t, dtype=torch.long)
        mask[i, :len(t)] = True

    labels_tensor = torch.tensor(label, dtype=torch.long)
    numeric_features = torch.tensor(features, dtype=torch.float32)

    return matrix_initial, mask, labels_tensor, numeric_features


# neural network 
class PasswordCNN(nn.Module):
    def __init__(self, vocab_size, emb_dim=16, n_classes=3, num_extra_features=2):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, emb_dim, 0)
        self.conv1 = nn.Conv1d(emb_dim, 32, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(32, 32, kernel_size=3, padding=1)
        self.Dropout = nn.Dropout(0.2)
        self.Classifier = nn.Linear(32 + num_extra_features, n_classes)

    def forward(self, x, mask, numeric_features):
        emb = self.embedding(x).transpose(1, 2)
        h = torch.relu(self.conv1(emb))
        h = self.Dropout(h)
        h = torch.relu(self.conv2(h))
        mask3d = mask.unsqueeze(1)
        h = h.masked_fill(mask3d == False, float('-inf'))

        pooled = torch.max(h, dim=2)[0]
        pooled = torch.nan_to_num(pooled, nan=0.0, neginf=0.0, posinf=0.0)

        combined = torch.cat([pooled, numeric_features], dim=1)
        return self.Classifier(combined)


def train_model(model, train_loader, val_loader, epochs=100, patience=10, device=torch.device("cpu")):
    # 1. Assicura che i pesi del modello risiedano sulla memoria della GPU
    model = model.to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001, weight_decay=1e-4)
    criterion = nn.CrossEntropyLoss()
    best_val_loss = float('inf')
    patience_counter = 0

    for epoch in range(epochs):
        model.train()
        for x, mask, y, num_feats in train_loader:
            # 2. Spostamento del batch di training sul dispositivo di calcolo
            x = x.to(device)
            mask = mask.to(device)
            y = y.to(device)
            num_feats = num_feats.to(device)

            optimizer.zero_grad()
            out = model(x, mask, num_feats)
            loss = criterion(out, y)
            loss.backward()
            optimizer.step()

        model.eval()
        val_loss = 0.0
        with torch.no_grad():
            for x, mask, y, num_feats in val_loader:
                x = x.to(device)
                mask = mask.to(device)
                y = y.to(device)
                num_feats = num_feats.to(device)

                out = model(x, mask, num_feats)
                val_loss += criterion(out, y).item()
        val_loss /= len(val_loader)

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            patience_counter = 0
            torch.save(model.state_dict(), "best_cnn_model.pt")
        else:
            patience_counter += 1
            if patience_counter >= patience:
                print(f"Early stopping all'epoca {epoch}")
                break

    model.load_state_dict(torch.load("best_cnn_model.pt", map_location=device))
    return model


def predict_password(model, tokenizer, password: str, device=torch.device("cpu")) -> dict:
    model.eval()

    tokens = tokenizer.encode(password) if password else [tokenizer.char2idx[tokenizer.unk]]

    x = torch.tensor([tokens], dtype=torch.long).to(device)
    mask = torch.ones((1, len(tokens)), dtype=torch.bool).to(device)

    raw_length = float(len(password))
    counts = Counter(password)
    raw_entropy = -sum((c / raw_length) * math.log2(c / raw_length) for c in counts.values()) if raw_length > 0 else 0.0

    norm_length = min(raw_length / 32.0, 1.0)
    norm_entropy = min(raw_entropy / 5.0, 1.0)
    num_feats = torch.tensor([[norm_length, norm_entropy]], dtype=torch.float32).to(device)

    with torch.no_grad():
        logits = model(x, mask, num_feats)
        probabilities = torch.softmax(logits, dim=1).squeeze(0)
        predicted_class_id = torch.argmax(probabilities).item()

    class_names = {0: "Debole", 1: "Media", 2: "Forte"}

    return {
        "password": password,
        "classe": class_names.get(predicted_class_id, "Sconosciuta"),
        "classe_id": predicted_class_id,
        "probabilita": {
            "debole": round(probabilities[0].item(), 4),
            "media": round(probabilities[1].item(), 4),
            "forte": round(probabilities[2].item(), 4)
        }
    }


if __name__ == "__main__":
    device = torch.device(
        "mps" if torch.backends.mps.is_available() 
        else "cuda" if torch.cuda.is_available() 
        else "cpu"
    )
    print(f"Acceleratore hardware selezionato: {device}")

    tokenizer = Tokenizer()
    dataset = PasswordDataset("passwords_full.csv", tokenizer)

    train_size = int(0.8 * len(dataset))
    val_size = len(dataset) - train_size
    train_data, val_data = random_split(dataset, [train_size, val_size])

    train_loader = DataLoader(train_data, batch_size=64, shuffle=True, collate_fn=collate_fn)
    val_loader = DataLoader(val_data, batch_size=64, shuffle=False, collate_fn=collate_fn)

    model = PasswordCNN(
        vocab_size=tokenizer.vocab_size,
        emb_dim=16,
        n_classes=3,
        num_extra_features=2
    ).to(device)

    print("Inizio addestramento...")
    trained_model = train_model(model, train_loader, val_loader, epochs=100, patience=5, device=device)
    print("Addestramento completato!")

    test_pwd = "P@ssw0rdSicura2026!"
    risultato = predict_password(trained_model, tokenizer, test_pwd, device=device)
    print("\nRisultato inferenza:")
    print(risultato)