"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.auth = void 0;
const better_auth_1 = require("better-auth");
const prisma_1 = require("better-auth/adapters/prisma");
const prisma_2 = require("./prisma");
exports.auth = (0, better_auth_1.betterAuth)({
    database: (0, prisma_1.prismaAdapter)(prisma_2.prisma, {
        provider: 'postgresql',
    }),
    emailAndPassword: {
        enabled: true,
        disableSignUp: true,
    },
    trustedOrigins: process.env.CLIENT_URL ? [process.env.CLIENT_URL] : [],
    advanced: {
        cookiePrefix: 'helpdesk',
        defaultCookieAttributes: {
            secure: process.env.NODE_ENV === 'production',
            httpOnly: true,
            sameSite: 'lax',
        },
    },
    user: {
        additionalFields: {
            role: {
                type: 'string',
                input: false,
            },
        },
    },
});
