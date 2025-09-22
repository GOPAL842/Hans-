Short Video App – Realtime Chat Module (RN + Node/Express + Socket.IO)

> Production-ready starter to plug a WhatsApp/Instagram-style DM into your short‑video app (Vedik/Hans Reels, etc.). Includes backend (Node/Express + MongoDB + Socket.IO), JWT auth, typing/online status, message receipts, media upload stubs, and React Native (Expo) UI with Zustand store.




---

1) Backend (Node + Express + MongoDB + Socket.IO)

1.1 Folder structure

server/
  .env                         # MONGO_URI, JWT_SECRET, CORS_ORIGIN
  package.json
  tsconfig.json
  src/
    index.ts                   # entry, http + socket.io
    config/env.ts
    utils/jwt.ts
    utils/multer.ts            # (stub) media/file uploads
    middleware/auth.ts
    models/User.ts
    models/Conversation.ts
    models/Message.ts
    routes/auth.ts
    routes/users.ts
    routes/conversations.ts
    routes/messages.ts
    sockets/chat.ts

1.2 package.json

{
  "name": "sv-chat-server",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "tsx watch src/index.ts",
    "start": "node dist/index.js",
    "build": "tsc"
  },
  "dependencies": {
    "bcryptjs": "^2.4.3",
    "cors": "^2.8.5",
    "dotenv": "^16.4.5",
    "express": "^4.19.2",
    "express-rate-limit": "^7.4.0",
    "helmet": "^7.1.0",
    "jsonwebtoken": "^9.0.2",
    "mongoose": "^8.4.4",
    "morgan": "^1.10.0",
    "multer": "^1.4.5-lts.1",
    "socket.io": "^4.7.5"
  },
  "devDependencies": {
    "@types/bcryptjs": "^2.4.2",
    "@types/express": "^4.17.21",
    "@types/jsonwebtoken": "^9.0.5",
    "@types/mongoose": "^5.11.97",
    "@types/multer": "^1.4.12",
    "@types/node": "^20.14.10",
    "@types/cors": "^2.8.17",
    "@types/morgan": "^1.9.6",
    "tsx": "^4.15.7",
    "typescript": "^5.4.5"
  }
}

1.3 src/config/env.ts

import dotenv from 'dotenv';
dotenv.config();
export const ENV = {
  PORT: process.env.PORT ? Number(process.env.PORT) : 5000,
  MONGO_URI: process.env.MONGO_URI || 'mongodb://localhost:27017/sv_chat',
  JWT_SECRET: process.env.JWT_SECRET || 'change-me',
  CORS_ORIGIN: process.env.CORS_ORIGIN || '*',
};

1.4 src/utils/jwt.ts

import jwt from 'jsonwebtoken';
import { ENV } from '../config/env';
export type JwtPayload = { id: string };
export const signToken = (id: string) => jwt.sign({ id }, ENV.JWT_SECRET, { expiresIn: '30d' });
export const verifyToken = (token: string) => jwt.verify(token, ENV.JWT_SECRET) as JwtPayload;

1.5 src/middleware/auth.ts

import { Request, Response, NextFunction } from 'express';
import { verifyToken } from '../utils/jwt';

export interface AuthedRequest extends Request { userId?: string }

export const auth = (req: AuthedRequest, res: Response, next: NextFunction) => {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ message: 'No token' });
  try {
    const token = header.split(' ')[1];
    const payload = verifyToken(token);
    req.userId = payload.id;
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

1.6 src/models

User.ts

import { Schema, model } from 'mongoose';

const UserSchema = new Schema({
  username: { type: String, required: true, unique: true, index: true },
  avatar: String,
  password: { type: String, required: true },
  isOnline: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now },
}, { timestamps: true });

export const User = model('User', UserSchema);

Conversation.ts

import { Schema, model, Types } from 'mongoose';

const ConversationSchema = new Schema({
  participants: [{ type: Schema.Types.ObjectId, ref: 'User', index: true }],
  lastMessage: { type: Schema.Types.ObjectId, ref: 'Message' },
}, { timestamps: true });

ConversationSchema.index({ participants: 1 });
export const Conversation = model('Conversation', ConversationSchema);

Message.ts

import { Schema, model } from 'mongoose';

const MessageSchema = new Schema({
  conversation: { type: Schema.Types.ObjectId, ref: 'Conversation', index: true },
  sender: { type: Schema.Types.ObjectId, ref: 'User', index: true },
  type: { type: String, enum: ['text','image','video','audio','file'], default: 'text' },
  text: String,
  mediaUrl: String,
  status: { type: String, enum: ['sent','delivered','read'], default: 'sent' },
}, { timestamps: true });

MessageSchema.index({ conversation: 1, createdAt: -1 });
export const Message = model('Message', MessageSchema);

1.7 src/routes/auth.ts

import { Router } from 'express';
import { User } from '../models/User';
import bcrypt from 'bcryptjs';
import { signToken } from '../utils/jwt';

const router = Router();

router.post('/register', async (req, res) => {
  const { username, password, avatar } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'username & password required' });
  const exists = await User.findOne({ username });
  if (exists) return res.status(409).json({ message: 'username taken' });
  const hash = await bcrypt.hash(password, 10);
  const user = await User.create({ username, password: hash, avatar });
  const token = signToken(user.id);
  res.json({ token, user: { id: user.id, username, avatar } });
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(401).json({ message: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ message: 'Invalid credentials' });
  const token = signToken(user.id);
  res.json({ token, user: { id: user.id, username: user.username, avatar: user.avatar } });
});

export default router;

1.8 src/routes/users.ts

import { Router } from 'express';
import { auth, AuthedRequest } from '../middleware/auth';
import { User } from '../models/User';

const router = Router();

router.get('/me', auth, async (req: AuthedRequest, res) => {
  const me = await User.findById(req.userId).select('-password');
  res.json(me);
});

router.get('/search', auth, async (req: AuthedRequest, res) => {
  const q = (req.query.q as string) || '';
  const users = await User.find({ username: { $regex: q, $options: 'i' } }).select('username avatar');
  res.json(users);
});

export default router;

1.9 src/routes/conversations.ts

import { Router } from 'express';
import { auth, AuthedRequest } from '../middleware/auth';
import { Conversation } from '../models/Conversation';
import { Message } from '../models/Message';

const router = Router();

// List my conversations
router.get('/', auth, async (req: AuthedRequest, res) => {
  const convos = await Conversation.find({ participants: req.userId })
    .populate('lastMessage')
    .sort({ updatedAt: -1 });
  res.json(convos);
});

// Create or get 1:1 conversation
router.post('/with/:otherId', auth, async (req: AuthedRequest, res) => {
  const { otherId } = req.params;
  let convo = await Conversation.findOne({ participants: { $all: [req.userId, otherId], $size: 2 } });
  if (!convo) convo = await Conversation.create({ participants: [req.userId, otherId] });
  res.json(convo);
});

// Get messages
router.get('/:id/messages', auth, async (req: AuthedRequest, res) => {
  const { id } = req.params;
  const { cursor } = req.query;
  const pageSize = 30;
  const filter: any = { conversation: id };
  if (cursor) filter._id = { $lt: cursor };

  const msgs = await Message.find(filter).sort({ _id: -1 }).limit(pageSize);
  res.json({ items: msgs, nextCursor: msgs.length ? msgs[msgs.length-1]._id : null });
});

export default router;

1.10 src/routes/messages.ts

import { Router } from 'express';
import { auth, AuthedRequest } from '../middleware/auth';
import { Message } from '../models/Message';
import { Conversation } from '../models/Conversation';

const router = Router();

router.post('/', auth, async (req: AuthedRequest, res) => {
  const { conversation, text, type, mediaUrl } = req.body;
  const msg = await Message.create({ conversation, sender: req.userId, text, type, mediaUrl });
  await Conversation.findByIdAndUpdate(conversation, { lastMessage: msg._id });
  res.json(msg);
});

router.post('/:id/read', auth, async (req: AuthedRequest, res) => {
  const { id } = req.params;
  const msg = await Message.findByIdAndUpdate(id, { status: 'read' }, { new: true });
  res.json(msg);
});

export default router;

1.11 src/sockets/chat.ts

import { Server } from 'socket.io';
import { verifyToken } from '../utils/jwt';
import { Message } from '../models/Message';
import { Conversation } from '../models/Conversation';
import { User } from '../models/User';

export const initChatSocket = (io: Server) => {
  io.use((socket, next) => {
    try {
      const token = (socket.handshake.auth?.token || socket.handshake.headers['x-token']) as string;
      const { id } = verifyToken(token);
      (socket as any).userId = id;
      next();
    } catch (e) { next(new Error('Unauthorized')); }
  });

  io.on('connection', async (socket) => {
    const userId = (socket as any).userId as string;
    await User.findByIdAndUpdate(userId, { isOnline: true, lastSeen: new Date() });
    socket.join(userId); // personal room for direct emits

    socket.on('typing', ({ conversation, to, isTyping }) => {
      io.to(to).emit('typing', { conversation, from: userId, isTyping });
    });

    socket.on('send:message', async (payload, cb) => {
      const { conversation, text, type, mediaUrl } = payload;
      const msg = await Message.create({ conversation, sender: userId, text, type, mediaUrl });
      await Conversation.findByIdAndUpdate(conversation, { lastMessage: msg._id });
      io.emit(`conversation:${conversation}:new`, msg);
      io.to(userId).emit('receipt', { id: msg._id, status: 'sent' });
      cb?.(msg);
    });

    socket.on('read:message', async ({ id, conversation, to }) => {
      const updated = await Message.findByIdAndUpdate(id, { status: 'read' }, { new: true });
      io.to(to).emit('receipt', { id, status: 'read', conversation });
    });

    socket.on('disconnect', async () => {
      await User.findByIdAndUpdate(userId, { isOnline: false, lastSeen: new Date() });
    });
  });
};

1.12 src/index.ts

import express from 'express';
import http from 'http';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import mongoose from 'mongoose';
import { ENV } from './config/env';
import authRoutes from './routes/auth';
import userRoutes from './routes/users';
import convoRoutes from './routes/conversations';
import messageRoutes from './routes/messages';
import { Server } from 'socket.io';
import { initChatSocket } from './sockets/chat';
import rateLimit from 'express-rate-limit';

const app = express();
app.use(cors({ origin: ENV.CORS_ORIGIN }));
app.use(helmet());
app.use(morgan('dev'));
app.use(express.json({ limit: '5mb' }));
app.use(rateLimit({ windowMs: 60_000, max: 120 }));

app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/conversations', convoRoutes);
app.use('/api/messages', messageRoutes);

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: ENV.CORS_ORIGIN } });
initChatSocket(io);

mongoose.connect(ENV.MONGO_URI).then(() => {
  server.listen(ENV.PORT, () => console.log(`API up on :${ENV.PORT}`));
});


---

2) Frontend (React Native + Expo + Zustand + Socket.IO client)

2.1 Folder structure

app/
  App.tsx
  src/
    api/client.ts
    store/chat.ts
    components/MessageBubble.tsx
    components/InputBar.tsx
    screens/ChatListScreen.tsx
    screens/ChatScreen.tsx
    screens/NewChatModal.tsx

2.2 package.json (client)

{
  "name": "sv-chat-client",
  "version": "1.0.0",
  "main": "node_modules/expo/AppEntry.js",
  "scripts": { "start": "expo start" },
  "dependencies": {
    "expo": "~51.0.0",
    "expo-image-picker": "~15.0.7",
    "expo-notifications": "~0.28.16",
    "react": "18.2.0",
    "react-native": "0.74.3",
    "@react-navigation/native": "^6.1.17",
    "@react-navigation/native-stack": "^6.9.26",
    "zustand": "^4.5.2",
    "socket.io-client": "^4.7.5",
    "axios": "^1.7.2"
  }
}

2.3 src/api/client.ts

import axios from 'axios';
export const API_URL = 'http://10.0.2.2:5000/api'; // Android emulator; change to your server IP

export const api = axios.create({ baseURL: API_URL });

export const setAuthToken = (token: string | null) => {
  if (token) api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  else delete api.defaults.headers.common['Authorization'];
};

2.4 src/store/chat.ts

import { create } from 'zustand';
import { io, Socket } from 'socket.io-client';

export type Message = {
  _id: string; conversation: string; sender: string; text?: string; type: string; mediaUrl?: string; status: 'sent'|'delivered'|'read'; createdAt: string;
}

type State = {
  token: string | null;
  userId: string | null;
  socket: Socket | null;
  conversations: Record<string, Message[]>; // convoId -> messages
  typing: Record<string, boolean>;          // convoId -> isTyping
  connect: (token: string, userId: string, socketUrl: string) => void;
  disconnect: () => void;
  addMessage: (m: Message) => void;
  setTyping: (convo: string, is: boolean) => void;
}

export const useChat = create<State>((set, get) => ({
  token: null,
  userId: null,
  socket: null,
  conversations: {},
  typing: {},
  connect: (token, userId, socketUrl) => {
    const socket = io(socketUrl, { auth: { token } });
    socket.on('connect', () => set({ socket, token, userId }));
    socket.onAny((event, payload) => { /* debug */ });
    socket.on('receipt', ({ id, status, conversation }) => {
      const list = get().conversations[conversation] || [];
      set({ conversations: { ...get().conversations, [conversation]: list.map(m => m._id===id? { ...m, status }: m) } });
    });
    socket.on('typing', ({ conversation, isTyping }) => {
      set({ typing: { ...get().typing, [conversation]: isTyping } });
    });
    socket.onAny((event, payload) => {
      if (typeof event === 'string' && event.startsWith('conversation:') && event.endsWith(':new')) {
        const msg = payload as Message;
        const list = get().conversations[msg.conversation] || [];
        set({ conversations: { ...get().conversations, [msg.conversation]: [msg, ...list] } });
      }
    });
  },
  disconnect: () => {
    get().socket?.disconnect();
    set({ socket: null });
  },
  addMessage: (m) => {
    const list = get().conversations[m.conversation] || [];
    set({ conversations: { ...get().conversations, [m.conversation]: [m, ...list] } });
  },
  setTyping: (convo, is) => set({ typing: { ...get().typing, [convo]: is } }),
}));

2.5 components/MessageBubble.tsx

import React from 'react';
import { View, Text } from 'react-native';

export default function MessageBubble({ mine, text, status }: { mine: boolean; text?: string; status?: string }) {
  return (
    <View style={{ alignSelf: mine ? 'flex-end' : 'flex-start', backgroundColor: mine ? '#daf8e3' : '#eee', padding: 10, marginVertical: 4, borderRadius: 12, maxWidth: '80%' }}>
      {!!text && <Text style={{ fontSize: 16 }}>{text}</Text>}
      {mine && <Text style={{ fontSize: 10, opacity: 0.6, marginTop: 4 }}>{status}</Text>}
    </View>
  );
}

2.6 components/InputBar.tsx

import React, { useState, useEffect } from 'react';
import { View, TextInput, TouchableOpacity, Text } from 'react-native';
import { useChat } from '../store/chat';

export default function InputBar({ conversation, to }: { conversation: string; to: string }) {
  const [value, setValue] = useState('');
  const { socket } = useChat();

  useEffect(() => {
    const id = setTimeout(() => socket?.emit('typing', { conversation, to, isTyping: value.length>0 }), 100);
    return () => clearTimeout(id);
  }, [value]);

  const send = () => {
    if (!value.trim()) return;
    socket?.emit('send:message', { conversation, text: value, type: 'text' }, (msg: any) => {
      setValue('');
    });
  };

  return (
    <View style={{ flexDirection: 'row', padding: 8, gap: 8 }}>
      <TextInput value={value} onChangeText={setValue} placeholder="Type a message" style={{ flex: 1, backgroundColor: '#f2f2f2', borderRadius: 24, paddingHorizontal: 14, paddingVertical: 10 }} />
      <TouchableOpacity onPress={send} style={{ backgroundColor: '#0ea5e9', paddingHorizontal: 16, justifyContent: 'center', borderRadius: 24 }}>
        <Text style={{ color: 'white', fontWeight: '700' }}>Send</Text>
      </TouchableOpacity>
    </View>
  );
}

2.7 screens/ChatListScreen.tsx

import React, { useEffect, useState } from 'react';
import { View, Text, FlatList, TouchableOpacity } from 'react-native';
import { api } from '../api/client';

export default function ChatListScreen({ navigation }: any) {
  const [items, setItems] = useState<any[]>([]);
  useEffect(() => { (async () => { const r = await api.get('/conversations'); setItems(r.data); })(); }, []);

  return (
    <View style={{ flex: 1, padding: 12 }}>
      <FlatList data={items} keyExtractor={(i) => i._id}
        renderItem={({ item }) => (
          <TouchableOpacity onPress={() => navigation.navigate('Chat', { conversation: item._id })} style={{ paddingVertical: 14, borderBottomWidth: 1, borderColor: '#eee' }}>
            <Text style={{ fontSize: 16, fontWeight: '600' }}>Conversation {item._id.slice(-5)}</Text>
            {item.lastMessage && <Text numberOfLines={1} style={{ opacity: 0.6 }}>{item.lastMessage.text || item.lastMessage.type}</Text>}
          </TouchableOpacity>
        )}
      />
    </View>
  );
}

2.8 screens/ChatScreen.tsx

import React, { useEffect, useState } from 'react';
import { View, Text, FlatList } from 'react-native';
import { api } from '../api/client';
import { useChat } from '../store/chat';
import MessageBubble from '../components/MessageBubble';
import InputBar from '../components/InputBar';

export default function ChatScreen({ route }: any) {
  const { conversation } = route.params as { conversation: string };
  const { conversations, typing, userId } = useChat();
  const [messages, setMessages] = useState<any[]>([]);

  useEffect(() => { (async () => {
    const r = await api.get(`/conversations/${conversation}/messages`);
    setMessages(r.data.items);
  })(); }, [conversation]);

  const live = conversations[conversation] || [];
  const merged = [...live, ...messages.filter(m => !live.find(l => l._id === m._id))];

  return (
    <View style={{ flex: 1, padding: 12 }}>
      <FlatList inverted data={merged} keyExtractor={(i) => i._id}
        renderItem={({ item }) => (
          <MessageBubble mine={item.sender === userId} text={item.text} status={item.status} />
        )}
      />
      {!!typing[conversation] && <Text style={{ marginLeft: 8, opacity: 0.6 }}>Typing…</Text>}
      <InputBar conversation={conversation} to={'' /* supply other user id from convo meta */} />
    </View>
  );
}

2.9 screens/NewChatModal.tsx

import React, { useEffect, useState } from 'react';
import { View, TextInput, FlatList, TouchableOpacity, Text } from 'react-native';
import { api } from '../api/client';

export default function NewChatModal({ navigation }: any) {
  const [q, setQ] = useState('');
  const [users, setUsers] = useState<any[]>([]);
  useEffect(() => { (async () => { const r = await api.get(`/users/search?q=${encodeURIComponent(q)}`); setUsers(r.data); })(); }, [q]);

  return (
    <View style={{ flex: 1, padding: 12 }}>
      <TextInput value={q} onChangeText={setQ} placeholder="Search users" style={{ backgroundColor: '#f2f2f2', borderRadius: 12, padding: 10 }} />
      <FlatList data={users} keyExtractor={(i) => i._id} renderItem={({ item }) => (
        <TouchableOpacity onPress={async () => {
          const r = await api.post(`/conversations/with/${item._id}`);
          navigation.replace('Chat', { conversation: r.data._id });
        }} style={{ paddingVertical: 12, borderBottomWidth: 1, borderColor: '#eee' }}>
          <Tex style={{ fontSize: 16 }}>{item.username}</Text>
        </TouchableOpacity>
      )} />
    </View>
  );
}
```

### 2.10 App.tsx (minimal wiring)
```tsx
import React, { useEffect } from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import ChatListScreen from './src/screens/ChatListScreen';
import ChatScreen from './src/screens/ChatScreen';
import NewChatModal from './src/screens/NewChatModal';
import { useChat } from './src/store/chat';

const Stack = createNativeStackNavigator();

export default function App() {
  const { connect } = useChat();

  useEffect(() => {
    // TODO: Replace with real auth flow
    const token = 'YOUR_JWT';
    const userId = 'ME';
    connect(token, userId, 'http://10.0.2.2:5000');
  }, []);

  return (
    <NavigationContainer>
      <Stack.Navigator>
        <Stack.Screen name="Chats" component={ChatListScreen} />
        <Stack.Screen name="Chat" component={ChatScreen} />
        <Stack.Screen name="NewChat" component={NewChatModal} />
      </Stack.Navigator>
    </NavigationContainer>
  );
}
```

---

## 3) Integration Notes (Vedik/Hans Reels)
- Reels Profile → add "Message" CTA → create/get conversation → navigate to ChatScreen.
- Use same JWT as your existing auth (set `Authorization: Bearer <token>` for REST; `auth.token` for Socket.IO).
- Uploads: wire `utils/multer.ts` to S3/Cloudinary/Firebase Storage. Save returned `mediaUrl` in `Message`.
- Push notifications: on `send:message`, also queue FCM/APNs push to the recipient.
- Moderation hooks: add middleware to scan `text`/media for abuse; auto-block if needed.
- Monetization: add pay-to-message for Business accounts or ads between message batches if desired.

---

## 4) Quick Start
1) **Server:**
```bash
cd server
npm i
cp .env.example .env  # create .env with MONGO_URI, JWT_SECRET, CORS_ORIGIN
npm run dev
```
2) **Client (Expo):**
```bash
cd app
npm i
npm run start
