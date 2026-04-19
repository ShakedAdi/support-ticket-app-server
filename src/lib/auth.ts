import { betterAuth } from 'better-auth';
import { prismaAdapter } from 'better-auth/adapters/prisma';
import { prisma } from './prisma';

export const auth = betterAuth({
  database: prismaAdapter(prisma, {
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
