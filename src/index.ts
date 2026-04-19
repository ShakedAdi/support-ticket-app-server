import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { toNodeHandler } from 'better-auth/node';
import { prisma } from './lib/prisma';
import { auth } from './lib/auth';
import { requireAuth } from './middleware/requireAuth';
import { requireAdmin } from './middleware/requireAdmin';

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

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

process.on('beforeExit', async () => {
  await prisma.$disconnect();
});
