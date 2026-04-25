"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const zod_1 = require("zod");
const prisma_1 = require("../lib/prisma");
const router = (0, express_1.Router)();
const inboundEmailSchema = zod_1.z
    .object({
    From: zod_1.z.string().email('Valid From email is required'),
    Subject: zod_1.z.any().superRefine((val, ctx) => {
        if (typeof val !== 'string' || val.length === 0) {
            ctx.addIssue({ code: 'custom', message: 'Subject is required' });
        }
    }),
    TextBody: zod_1.z.string().optional(),
    HtmlBody: zod_1.z.string().optional(),
})
    .refine((d) => d.TextBody || d.HtmlBody, { message: 'TextBody or HtmlBody is required' });
function stripHtml(html) {
    return html.replace(/<[^>]+>/g, '').trim();
}
router.post('/inbound-email', async (req, res) => {
    const result = inboundEmailSchema.safeParse(req.body);
    if (!result.success) {
        res.status(400).json({ error: result.error.issues[0].message });
        return;
    }
    const { From, Subject, TextBody, HtmlBody } = result.data;
    const body = TextBody ?? stripHtml(HtmlBody);
    const ticket = await prisma_1.prisma.ticket.create({
        data: { subject: Subject, body, senderEmail: From },
        select: { id: true, subject: true, senderEmail: true, status: true, createdAt: true },
    });
    res.status(201).json(ticket);
});
exports.default = router;
