import 'dotenv/config';
import * as Sentry from '@sentry/node';

Sentry.init({
  dsn: process.env.SENTRY_DSN,
  environment: process.env.NODE_ENV ?? 'development',
  // Set to 0.1 in production; 1.0 captures all traces (fine for dev/low-traffic)
  tracesSampleRate: process.env.NODE_ENV === 'production' ? 0.1 : 1.0,
});
