import arcjet, { shield, detectBot } from '@arcjet/node';

const aj = arcjet({
  // Get your site key from https://app.arcjet.com and set it as an environment
  // variable rather than hard coding.
  key: process.env.ARCJET_KEY,
  rules: [
    // Shield protects your app from common attacks e.g. SQL injection
    shield({ mode: 'LIVE' }),
    detectBot({
      mode: 'DRY_RUN',
      allow: [
        'CATEGORY:SEARCH_ENGINE',
        'CATEGORY:PREVIEW',
        'CATEGORY:TOOL',
        'CATEGORY:PROGRAMMATIC',
      ],
    }),
  ],
});

export default aj;
