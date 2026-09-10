export interface ContactBundle {
  label: string;
  value: string;
}

export interface ChatContact {
  id: string;
  name: string;
  handle: string;
  avatar: string;
  lastMessage: string;
  time: string;
  unread: number;
  online: boolean;
  pqxdh: boolean;
  mailbox: boolean;
  verified: "ml-dsa" | "xeddsa" | "none";
  publicId: string;
  fingerprint: string;
  addedOn: string;
  bundle: ContactBundle[];
}

export interface ChatMessage {
  id: number;
  from: "me" | "them";
  text: string;
  time: string;
  type: "CHAT_MESSAGE" | "SESSION_INIT" | "MAILBOX_PUT" | "FRIEND_REQUEST";
  security?: string[];
}

export const CONTACTS: ChatContact[] = [
  {
    id: "alice",
    name: "Alice Rivest",
    handle: "alice_87",
    avatar: "AR",
    lastMessage: "TLS 1.3 + X25519MLKEM768 confirmed on my side.",
    time: "14:32",
    unread: 2,
    online: true,
    pqxdh: true,
    mailbox: false,
    verified: "ml-dsa",
    publicId: "ALICE-87-F3A9-C20D",
    fingerprint: "A1:F2:3C:8E:4B:77:91:0D:5A:2E:C8:6F:3B:99:10:44",
    addedOn: "14 Aug 2026",
    bundle: [
      { label: "Identity key · ML-DSA", value: "2592 B" },
      { label: "Identity key · X25519", value: "32 B" },
      { label: "Signed PreKey · SPK", value: "X25519" },
      { label: "Last-resort · PQKEM", value: "ML-KEM-768" },
    ],
  },
  {
    id: "bob",
    name: "Bob Shamir",
    handle: "bob_xk",
    avatar: "BS",
    lastMessage: "Bundle 0x0A received, session init complete.",
    time: "12:07",
    unread: 0,
    online: false,
    pqxdh: true,
    mailbox: true,
    verified: "xeddsa",
    publicId: "BOB-XK-77E2-91B4",
    fingerprint: "7C:11:9E:2D:6A:F8:B3:40:9D:C5:22:8F:14:6E:88:50",
    addedOn: "02 Aug 2026",
    bundle: [
      { label: "Identity key · ML-DSA", value: "2592 B" },
      { label: "Identity key · X25519", value: "32 B" },
      { label: "Signed PreKey · SPK", value: "X25519" },
      { label: "Last-resort · PQKEM", value: "ML-KEM-768" },
    ],
  },
  {
    id: "carol",
    name: "Carol Adleman",
    handle: "carol_pq",
    avatar: "CA",
    lastMessage: "Send the mailbox ciphertext via 0x06 when ready.",
    time: "09:41",
    unread: 5,
    online: true,
    pqxdh: true,
    mailbox: false,
    verified: "none",
    publicId: "CAROL-PQ-1D08-A5C3",
    fingerprint: "0B:DA:64:1F:99:E2:77:AC:31:0E:4B:92:C7:5F:3A:6D",
    addedOn: "27 Jul 2026",
    bundle: [
      { label: "Identity key · ML-DSA", value: "2592 B" },
      { label: "Identity key · X25519", value: "32 B" },
      { label: "Signed PreKey · SPK", value: "X25519" },
      { label: "Last-resort · PQKEM", value: "ML-KEM-768" },
    ],
  },
  {
    id: "dave",
    name: "Dave Menezes",
    handle: "dave_25519",
    avatar: "DM",
    lastMessage: "IP_SHARE encrypted, holding until P2P link.",
    time: "Yesterday",
    unread: 0,
    online: false,
    pqxdh: false,
    mailbox: true,
    verified: "xeddsa",
    publicId: "DAVE-25519-5B44-8F07",
    fingerprint: "E9:33:2A:B8:4C:01:77:DF:58:9A:1C:44:6B:90:2E:75",
    addedOn: "19 Jul 2026",
    bundle: [
      { label: "Identity key · ML-DSA", value: "2592 B" },
      { label: "Identity key · X25519", value: "32 B" },
      { label: "Signed PreKey · SPK", value: "X25519" },
      { label: "Last-resort · PQKEM", value: "ML-KEM-768" },
    ],
  },
];

export const THREAD: ChatMessage[] = [
  {
    id: 1,
    from: "them",
    text: "Alice · ML-DSA-87 signed 0x0A · ML-KEM-768 · X25519",
    time: "14:28",
    type: "SESSION_INIT",
    security: ["ML-DSA-87", "ML-KEM-768", "X25519", "PQXDH"],
  },
  {
    id: 2,
    from: "me",
    text: "Received your PQXDH bundle. Ratchet initialized.",
    time: "14:29",
    type: "CHAT_MESSAGE",
    security: ["CHAT_MESSAGE 0x0B", "ML-KEM-768 shared", "AES-256-GCM"],
  },
  {
    id: 3,
    from: "them",
    text: "TLS 1.3 + X25519MLKEM768 confirmed on my side.",
    time: "14:32",
    type: "CHAT_MESSAGE",
    security: ["CHAT_MESSAGE 0x0B", "ML-DSA-87 signed"],
  },
];