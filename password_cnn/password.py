import json
import sys
from pathlib import Path

import torch

from predict import load_trained_model, predict


MAX_PASSWORD_BYTES = 256


def resource_path(filename: str) -> Path:
    if hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / filename

    return Path(__file__).resolve().parent / filename


def main() -> int:
    password_bytes = sys.stdin.buffer.read(MAX_PASSWORD_BYTES + 1)

    if len(password_bytes) > MAX_PASSWORD_BYTES:
        print("password troppo lunga", file=sys.stderr)
        return 2

    try:
        password = password_bytes.decode("utf-8")
    except UnicodeDecodeError:
        print("password UTF-8 non valida", file=sys.stderr)
        return 2

    try:
        model_path = resource_path("best_cnn_model.pt")

        model, tokenizer, device = load_trained_model(
            weights_path=str(model_path),
            device=torch.device("cpu"),
        )

        result = predict(
            model=model,
            tokenizer=tokenizer,
            password=password,
            device=device,
        )

        class_ids = {
            "Debole": 0,
            "Media": 1,
            "Forte": 2,
        }

        response = {
            "version": 1,
            "classe": result["classe"],
            "classe_id": class_ids[result["classe"]],
            "probabilita": result["probabilita"],
        }

        sys.stdout.write(
            json.dumps(
                response,
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
        sys.stdout.write("\n")
        sys.stdout.flush()

        return 0

    except Exception as exc:
        print(f"errore classificatore: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())