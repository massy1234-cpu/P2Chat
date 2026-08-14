export interface PhaseDef {
  id: string;
  name: string;
  bytecode: string;
  dir: "client" | "server" | "both";
  desc: string;
}

export const CLIENT_PHASES: PhaseDef[] = [
  { id: "req", name: "RegisterTokenReq", bytecode: "0x01", dir: "client", desc: "Client requests a registration token from the server." },
  { id: "challenge", name: "PowToken", bytecode: "0x02", dir: "server", desc: "Server issues an Argon2id PoW challenge (timestamp, salt, level, HMAC-MAC)." },
  { id: "proof", name: "ChallengeResponse", bytecode: "0x03", dir: "client", desc: "Client sends the solved nonce (8 bytes, big-endian)." },
  { id: "blind", name: "SignatureRequest", bytecode: "0x04", dir: "client", desc: "Client sends the blinded message M' (BLS G1 compressed, 48 bytes)." },
  { id: "token", name: "TokenEmission", bytecode: "0x05", dir: "server", desc: "Server returns the blind BLS signature (48 bytes); client unblinds it." },
];

export const WIRE_MESSAGES = [
  { code: "0x00", name: "DUMMY", desc: "Obfuscation traffic (ORAM)" },
  { code: "0x01", name: "REGISTER_REQ", desc: "UserID (32B) + PublicBundle" },
  { code: "0x02", name: "REGISTER_RES", desc: "OK / ERR" },
  { code: "0x03", name: "BUNDLE_REQUEST", desc: "TargetUserID" },
  { code: "0x04", name: "BUNDLE_RESPONSE", desc: "TargetUserID + PublicBundle" },
  { code: "0x05", name: "DUMMY_REQUEST", desc: "Random ID (ORAM)" },
  { code: "0x06", name: "MAILBOX_PUT", desc: "MailboxID + Ciphertext + TAG" },
  { code: "0x07", name: "MAILBOX_GET", desc: "MailboxID" },
  { code: "0x08", name: "MAILBOX_CONTENTS", desc: "[{Ciphertext + TAG}]" },
  { code: "0x09", name: "FRIEND_REQUEST", desc: "Encrypted message" },
  { code: "0x0A", name: "SESSION_INIT", desc: "PQXDH initial message" },
  { code: "0x0B", name: "CHAT_MESSAGE", desc: "Ratchet header + ciphertext" },
  { code: "0x0C", name: "IP_SHARE", desc: "Encrypted IP" },
];
