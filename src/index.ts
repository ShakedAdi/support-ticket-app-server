import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { randomBytes, scrypt } from 'node:crypto';
import { z } from 'zod';
import { toNodeHandler } from 'better-auth/node';
import { prisma } from './lib/prisma';
import { auth } from './lib/auth';
import { requireAuth } from './middleware/requireAuth';
import { requireAdmin } from './middleware/requireAdmin';
import { Role } from './generated/prisma/enums';

const createUserSchema = z.object({
  name: z.string().trim().min(3, 'Name must be at least 3 characters'),
  email: z.string().email('Valid email is required'),
  password: z.string().trim().min(8, 'Password must be at least 8 characters'),
});

async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString('hex');
  const key = await new Promise<Buffer>((resolve, reject) => {
    scrypt(
      password.normalize('NFKC'),
      salt,
      64,
      { N: 16384, r: 16, p: 1, maxmem: 128 * 16384 * 16 * 2 },
      (err, derivedKey) => (err ? reject(err) : resolve(derivedKey as Buffer))
    );
  });
  return `${salt}:${key.toString('hex')}`;
}

const app = express();
const PORT = process.env.PORT ?? 3000;

const clientUrl = process.env.CLIENT_URL;
if (!clientUrl) {
  console.error('FATAL: CLIENT_URL environment variable is required');
  process.exit(1);
}

app.use(helmet());
app.use(cors({ origin: clientUrl, credentials: true }));

// Must be mounted before express.json()
if (process.env.NODE_ENV === 'production') {
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later.' },
  });
  app.use('/api/auth', authLimiter);
}
app.all('/api/auth/*', toNodeHandler(auth));

app.use(express.json());

app.get('/api/users', requireAuth, requireAdmin, async (_req, res) => {
  const users = await prisma.user.findMany({
    select: { id: true, name: true, email: true, role: true, createdAt: true },
    orderBy: { createdAt: 'asc' },
  });
  res.json(users);
});

app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const result = createUserSchema.safeParse(req.body);
  if (!result.success) {
    res.status(400).json({ error: result.error.issues[0].message });
    return;
  }
  const { name, email, password } = result.data;

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    res.status(409).json({ error: 'A user with this email already exists' });
    return;
  }

  const id = randomBytes(16).toString('hex');
  const now = new Date();

  const user = await prisma.user.create({
    data: {
      id,
      name,
      email,
      emailVerified: true,
      role: Role.agent,
      createdAt: now,
      updatedAt: now,
      accounts: {
        create: {
          id: randomBytes(16).toString('hex'),
          accountId: id,
          providerId: 'credential',
          password: await hashPassword(password),
          createdAt: now,
          updatedAt: now,
        },
      },
    },
    select: { id: true, name: true, email: true, role: true, createdAt: true },
  });

  res.status(201).json(user);
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

process.on('beforeExit', async () => {
  await prisma.$disconnect();
});
