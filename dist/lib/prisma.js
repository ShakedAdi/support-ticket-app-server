"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.prisma = void 0;
const pg_1 = require("pg");
const adapter_pg_1 = require("@prisma/adapter-pg");
const client_1 = require("../generated/prisma/client");
const pool = new pg_1.Pool({
    user: process.env.PGUSER,
    password: process.env.PGPASSWORD,
    database: process.env.PGDATABASE,
    host: process.env.PGHOST || '/tmp',
    port: process.env.PGPORT ? parseInt(process.env.PGPORT) : 5432,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});
const adapter = new adapter_pg_1.PrismaPg(pool);
const globalForPrisma = globalThis;
exports.prisma = globalForPrisma.prisma ??
    new client_1.PrismaClient({
        adapter,
        log: process.env.NODE_ENV === 'development' ? ['query', 'error', 'warn'] : ['error'],
    });
if (process.env.NODE_ENV !== 'production') {
    globalForPrisma.prisma = exports.prisma;
}
