import 'dotenv/config';
import { randomBytes, scrypt } from 'node:crypto';
import { prisma } from '../src/lib/prisma';
import { Role } from '../src/generated/prisma/enums';

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

async function main() {
  const email = process.env.SEED_ADMIN_EMAIL!;
  const password = process.env.SEED_ADMIN_PASSWORD!;

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    console.log(`Admin user already exists: ${email}`);
    return;
  }

  const id = randomBytes(16).toString('hex');
  const now = new Date();

  await prisma.user.create({
    data: {
      id,
      name: 'Admin',
      email,
      emailVerified: true,
      role: Role.admin,
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
  });

  console.log(`Created admin user: ${email}`);
}

main()
  .catch((e) => { console.error(e); process.exit(1); })
  .finally(() => prisma.$disconnect());
