import torch
import torch.nn as nn
import string
import math
from collections import Counter

# 1. Definizione minima del Tokenizer (identico al training)
class Tokenizer:
    def __init__(self):
        self.pad = "<PAD>"
        self.unk = "<UNK>"
        d = [self.pad, self.unk] + list(string.ascii_letters + string.digits + string.punctuation)
        self.char2idx = {char: idx for idx, char in enumerate(d)}
        self.vocab_size = len(self.char2idx)

    def encode(self, text: str) -> list[int]:
        unk_id = self.char2idx[self.unk]
        return [self.char2idx.get(char, unk_id) for char in text]

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

def load_trained_model(weights_path: str = "best_cnn_model.pt", device: torch.device = None):
    if device is None:
        device = torch.device("mps" if torch.backends.mps.is_available() else "cuda" if torch.cuda.is_available() else "cpu")

    tokenizer = Tokenizer()
    
    model = PasswordCNN(vocab_size=tokenizer.vocab_size, emb_dim=16, n_classes=3, num_extra_features=2)
    
    state_dict = torch.load(weights_path, map_location=device, weights_only=True)
    model.load_state_dict(state_dict)
    
    model.to(device)
    model.eval()
    
    return model, tokenizer, device

def predict(model, tokenizer, password: str, device) -> dict:
    tokens = tokenizer.encode(password) if password else [tokenizer.char2idx[tokenizer.unk]]

    x = torch.tensor([tokens], dtype=torch.long).to(device)
    mask = torch.ones((1, len(tokens)), dtype=torch.bool).to(device)

    raw_len = float(len(password))
    counts = Counter(password)
    entropy = -sum((c / raw_len) * math.log2(c / raw_len) for c in counts.values()) if raw_len > 0 else 0.0

    norm_len = min(raw_len / 32.0, 1.0)
    norm_entropy = min(entropy / 5.0, 1.0)
    num_feats = torch.tensor([[norm_len, norm_entropy]], dtype=torch.float32).to(device)

    with torch.no_grad():
        logits = model(x, mask, num_feats)
        probs = torch.softmax(logits, dim=1).squeeze(0)
        predicted_class = torch.argmax(probs).item()

    labels = {0: "Debole", 1: "Media", 2: "Forte"}
    return {
        "password": password,
        "classe": labels[predicted_class],
        "probabilita": {
            "debole": round(probs[0].item(), 4),
            "media": round(probs[1].item(), 4),
            "forte": round(probs[2].item(), 4)
        }
    }

if __name__ == "__main__":
    model, tokenizer, device = load_trained_model("best_cnn_model.pt")

    esempi = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "Venomk34??", "112211221122"]
    for pwd in esempi:
        print(predict(model, tokenizer, pwd, device))