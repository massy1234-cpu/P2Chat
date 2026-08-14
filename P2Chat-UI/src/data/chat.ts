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
