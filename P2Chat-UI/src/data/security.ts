export const CRYPTO_KEYS = [
  { name: "ML-DSA-87", role: "identity + signatures", size: "48.9 KB private · 25.9 KB public", standard: "FIPS 204", used: "cross-signed IK, message signatures" },
  { name: "ML-KEM-768", role: "PQ key exchange", size: "24 KB private · 11.8 KB public", standard: "FIPS 203", used: "PQXDH ratchet init" },
  { name: "X25519", role: "classic ECDH + XEdDSA", size: "32 B keys", standard: "RFC 7748", used: "XEdDSA identity, fallback KEX" },
  { name: "Blind BLS (Boldyreva)", role: "registration token", size: "G1 compressed 48 B", standard: "BLS12-381", used: "anti-spam tokens, no ROS attack" },
];

export const HSM_OPTIONS = [
  { id: "se", name: "Secure Enclave", platform: "macOS · P-256 ECIES · CGo", note: "kSecKeyAlgorithm ECIES X963 SHA256 AESGCM" },
  { id: "tpm", name: "TPM 2.0", platform: "Linux / Windows · HMAC-combine + AES-256", note: "primary key persistent at NV 0x81000001" },
  { id: "soft", name: "Software (Argon2id)", platform: "all · AES-256-GCM", note: "security levels 1–3, memguard mlock" },
];
