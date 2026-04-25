---
name: Playwright E2E conventions for support-ticket-app
description: Test server port, API base URL, request fixture pattern, and file layout used across all E2E specs
type: project
---

Test server runs on port 3001 in the Playwright environment (not 3000). The `playwright.config.ts` webServer starts the Express server on port 3001 and the client on port 5174.

**Why:** The config maps `server` → port 3001 and `client` → port 5174 via `VITE_API_URL`. Production/dev defaults differ.

**How to apply:** Always use `http://localhost:3001` as `API_BASE` in E2E specs. Never use port 3000. For API-only tests (no browser UI), use `page.request.post/get/...` — not the standalone `request` fixture — because existing specs uniformly use `page.request` and this inherits browser cookies set during login flows.

Test file location: `e2e/` at the repo root (`support-ticket-app/e2e/`).

Selector conventions: `getByRole` first, `getByLabel` for inputs, `getByText` for readable content. CSS class selectors (e.g. `p.text-destructive`) are used sparingly for error messages that lack accessible roles.

Auth setup: no storageState file. Tests that need auth call a local `loginAsAdmin(page)` helper directly in each spec file.

API-only test pattern (no UI): use `page.request.post(url, { data: {...} })` and cast the JSON response to a typed interface — no `any`. Example from `users.spec.ts`:
```typescript
const body = await response.json() as { id: string };
```
