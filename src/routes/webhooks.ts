import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '../lib/prisma';

const router = Router();

const inboundEmailSchema = z
  .object({
    From: z.string().email('Valid From email is required'),
    Subject: z.string().min(1, 'Subject is required'),
    TextBody: z.string().optional(),
    HtmlBody: z.string().optional(),
  })
  .refine((d) => d.TextBody || d.HtmlBody, { message: 'TextBody or HtmlBody is required' });

function stripHtml(html: string): string {
  return html.replace(/<[^>]+>/g, '').trim();
}

router.post('/inbound-email', async (req, res) => {
  const result = inboundEmailSchema.safeParse(req.body);
  if (!result.success) {
    res.status(400).json({ error: result.error.issues[0].message });
    return;
  }

  const { From, Subject, TextBody, HtmlBody } = result.data;
  const body = TextBody ?? stripHtml(HtmlBody!);

  const ticket = await prisma.ticket.create({
    data: { subject: Subject, body, senderEmail: From },
    select: { id: true, subject: true, senderEmail: true, status: true, createdAt: true },
  });

  res.status(201).json(ticket);
});

export default router;
