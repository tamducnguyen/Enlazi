export const throttlerConfig = [
  { name: 'burst', ttl: 60_000, limit: 1 }, // spam-sensitive
  { name: 'low', ttl: 60_000, limit: 5 }, // API write
  { name: 'medium', ttl: 60_000, limit: 30 }, // API read
  { name: 'high', ttl: 60_000, limit: 100 }, // public endpoints
];
