export const throttlerConfig = [
  {
    name: 'low',
    ttl: 60_000,
    limit: 10,
  },
  {
    name: 'medium',
    ttl: 60_000,
    limit: 60,
  },
  {
    name: 'high',
    ttl: 60_000,
    limit: 300,
  },
];
