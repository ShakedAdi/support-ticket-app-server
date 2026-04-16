"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const dotenv_1 = __importDefault(require("dotenv"));
const node_1 = require("better-auth/node");
const prisma_1 = require("./lib/prisma");
const auth_1 = require("./lib/auth");
dotenv_1.default.config();
const app = (0, express_1.default)();
const PORT = process.env.PORT ?? 3000;
// Must be mounted before express.json()
app.all('/api/auth/*', (0, node_1.toNodeHandler)(auth_1.auth));
app.use((0, cors_1.default)({ origin: process.env.CLIENT_URL ?? 'http://localhost:5173', credentials: true }));
app.use(express_1.default.json());
app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
process.on('beforeExit', async () => {
    await prisma_1.prisma.$disconnect();
});
