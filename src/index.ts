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
import webhookRouter from './routes/webhooks';

const createUserSchema = z.object({
  name: z.string().trim().min(3, 'Name must be at least 3 characters'),
  email: z.string().email('Valid email is required'),
  password: z.string().trim().min(8, 'Password must be at least 8 characters'),
});

const updateUserSchema = z.object({
  name: z.string().trim().min(3, 'Name must be at least 3 characters'),
  email: z.string().email('Valid email is required'),
  currentPassword: z.string().min(1, 'Current password is required'),
  newPassword: z.string().min(8, 'New password must be at least 8 characters').optional().or(z.literal('')),
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

async function verifyPassword(input: string, stored: string): Promise<boolean> {
  const [salt, storedKey] = stored.split(':');
  const key = await new Promise<Buffer>((resolve, reject) => {
    scrypt(
      input.normalize('NFKC'),
      salt,
      64,
      { N: 16384, r: 16, p: 1, maxmem: 128 * 16384 * 16 * 2 },
      (err, derivedKey) => (err ? reject(err) : resolve(derivedKey as Buffer))
    );
  });
  return key.toString('hex') === storedKey;
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

app.use('/api/webhooks', webhookRouter);

app.get('/api/tickets', requireAuth, async (_req, res) => {
  const tickets = await prisma.ticket.findMany({
    orderBy: { createdAt: 'desc' },
    select: {
      id: true,
      subject: true,
      senderEmail: true,
      status: true,
      createdAt: true,
      assignedTo: { select: { id: true, name: true } },
    },
  });
  res.json(tickets);
});

app.get('/api/users', requireAuth, requireAdmin, async (_req, res) => {
  const users = await prisma.user.findMany({
    where: { deletedAt: null },
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

app.put('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;

  const result = updateUserSchema.safeParse(req.body);
  if (!result.success) {
    res.status(400).json({ error: result.error.issues[0].message });
    return;
  }
  const { name, email, currentPassword, newPassword } = result.data;

  const user = await prisma.user.findUnique({ where: { id }, select: { id: true, email: true } });
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  const account = await prisma.account.findFirst({
    where: { userId: id, providerId: 'credential' },
    select: { id: true, password: true },
  });
  if (!account?.password) {
    res.status(400).json({ error: 'No credential account found for this user' });
    return;
  }

  const valid = await verifyPassword(currentPassword, account.password);
  if (!valid) {
    res.status(401).json({ error: 'Current password is incorrect' });
    return;
  }

  if (email !== user.email) {
    const conflict = await prisma.user.findUnique({ where: { email } });
    if (conflict) {
      res.status(409).json({ error: 'A user with this email already exists' });
      return;
    }
  }

  const now = new Date();

  const updated = await prisma.$transaction(async (tx) => {
    const u = await tx.user.update({
      where: { id },
      data: { name, email, updatedAt: now },
      select: { id: true, name: true, email: true, role: true, createdAt: true },
    });
    if (newPassword) {
      await tx.account.update({
        where: { id: account.id },
        data: { password: await hashPassword(newPassword), updatedAt: now },
      });
    }
    return u;
  });

  res.json(updated);
});

app.delete('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;

  if (req.user?.id === id) {
    res.status(403).json({ error: 'You cannot delete your own account' });
    return;
  }

  const user = await prisma.user.findUnique({
    where: { id, deletedAt: null },
    select: { id: true },
  });
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  await prisma.$transaction([
    prisma.session.deleteMany({ where: { userId: id } }),
    prisma.user.update({ where: { id }, data: { deletedAt: new Date() } }),
  ]);

  res.status(204).send();
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

process.on('beforeExit', async () => {
  await prisma.$disconnect();
});
