"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
require("dotenv/config");
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const helmet_1 = __importDefault(require("helmet"));
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const node_crypto_1 = require("node:crypto");
const zod_1 = require("zod");
const node_1 = require("better-auth/node");
const prisma_1 = require("./lib/prisma");
const auth_1 = require("./lib/auth");
const requireAuth_1 = require("./middleware/requireAuth");
const requireAdmin_1 = require("./middleware/requireAdmin");
const enums_1 = require("./generated/prisma/enums");
const webhooks_1 = __importDefault(require("./routes/webhooks"));
const createUserSchema = zod_1.z.object({
    name: zod_1.z.string().trim().min(3, 'Name must be at least 3 characters'),
    email: zod_1.z.string().email('Valid email is required'),
    password: zod_1.z.string().trim().min(8, 'Password must be at least 8 characters'),
});
const updateUserSchema = zod_1.z.object({
    name: zod_1.z.string().trim().min(3, 'Name must be at least 3 characters'),
    email: zod_1.z.string().email('Valid email is required'),
    currentPassword: zod_1.z.string().min(1, 'Current password is required'),
    newPassword: zod_1.z.string().min(8, 'New password must be at least 8 characters').optional().or(zod_1.z.literal('')),
});
async function hashPassword(password) {
    const salt = (0, node_crypto_1.randomBytes)(16).toString('hex');
    const key = await new Promise((resolve, reject) => {
        (0, node_crypto_1.scrypt)(password.normalize('NFKC'), salt, 64, { N: 16384, r: 16, p: 1, maxmem: 128 * 16384 * 16 * 2 }, (err, derivedKey) => (err ? reject(err) : resolve(derivedKey)));
    });
    return `${salt}:${key.toString('hex')}`;
}
async function verifyPassword(input, stored) {
    const [salt, storedKey] = stored.split(':');
    const key = await new Promise((resolve, reject) => {
        (0, node_crypto_1.scrypt)(input.normalize('NFKC'), salt, 64, { N: 16384, r: 16, p: 1, maxmem: 128 * 16384 * 16 * 2 }, (err, derivedKey) => (err ? reject(err) : resolve(derivedKey)));
    });
    return key.toString('hex') === storedKey;
}
const app = (0, express_1.default)();
const PORT = process.env.PORT ?? 3000;
const clientUrl = process.env.CLIENT_URL;
if (!clientUrl) {
    console.error('FATAL: CLIENT_URL environment variable is required');
    process.exit(1);
}
app.use((0, helmet_1.default)());
app.use((0, cors_1.default)({ origin: clientUrl, credentials: true }));
// Must be mounted before express.json()
if (process.env.NODE_ENV === 'production') {
    const authLimiter = (0, express_rate_limit_1.default)({
        windowMs: 15 * 60 * 1000,
        max: 20,
        standardHeaders: true,
        legacyHeaders: false,
        message: { error: 'Too many requests, please try again later.' },
    });
    app.use('/api/auth', authLimiter);
}
app.all('/api/auth/*', (0, node_1.toNodeHandler)(auth_1.auth));
app.use(express_1.default.json());
app.use('/api/webhooks', webhooks_1.default);
app.get('/api/users', requireAuth_1.requireAuth, requireAdmin_1.requireAdmin, async (_req, res) => {
    const users = await prisma_1.prisma.user.findMany({
        where: { deletedAt: null },
        select: { id: true, name: true, email: true, role: true, createdAt: true },
        orderBy: { createdAt: 'asc' },
    });
    res.json(users);
});
app.post('/api/users', requireAuth_1.requireAuth, requireAdmin_1.requireAdmin, async (req, res) => {
    const result = createUserSchema.safeParse(req.body);
    if (!result.success) {
        res.status(400).json({ error: result.error.issues[0].message });
        return;
    }
    const { name, email, password } = result.data;
    const existing = await prisma_1.prisma.user.findUnique({ where: { email } });
    if (existing) {
        res.status(409).json({ error: 'A user with this email already exists' });
        return;
    }
    const id = (0, node_crypto_1.randomBytes)(16).toString('hex');
    const now = new Date();
    const user = await prisma_1.prisma.user.create({
        data: {
            id,
            name,
            email,
            emailVerified: true,
            role: enums_1.Role.agent,
            createdAt: now,
            updatedAt: now,
            accounts: {
                create: {
                    id: (0, node_crypto_1.randomBytes)(16).toString('hex'),
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
app.put('/api/users/:id', requireAuth_1.requireAuth, requireAdmin_1.requireAdmin, async (req, res) => {
    const { id } = req.params;
    const result = updateUserSchema.safeParse(req.body);
    if (!result.success) {
        res.status(400).json({ error: result.error.issues[0].message });
        return;
    }
    const { name, email, currentPassword, newPassword } = result.data;
    const user = await prisma_1.prisma.user.findUnique({ where: { id }, select: { id: true, email: true } });
    if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
    }
    const account = await prisma_1.prisma.account.findFirst({
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
        const conflict = await prisma_1.prisma.user.findUnique({ where: { email } });
        if (conflict) {
            res.status(409).json({ error: 'A user with this email already exists' });
            return;
        }
    }
    const now = new Date();
    const updated = await prisma_1.prisma.$transaction(async (tx) => {
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
app.delete('/api/users/:id', requireAuth_1.requireAuth, requireAdmin_1.requireAdmin, async (req, res) => {
    const { id } = req.params;
    if (req.user?.id === id) {
        res.status(403).json({ error: 'You cannot delete your own account' });
        return;
    }
    const user = await prisma_1.prisma.user.findUnique({
        where: { id, deletedAt: null },
        select: { id: true },
    });
    if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
    }
    await prisma_1.prisma.$transaction([
        prisma_1.prisma.session.deleteMany({ where: { userId: id } }),
        prisma_1.prisma.user.update({ where: { id }, data: { deletedAt: new Date() } }),
    ]);
    res.status(204).send();
});
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
process.on('beforeExit', async () => {
    await prisma_1.prisma.$disconnect();
});
