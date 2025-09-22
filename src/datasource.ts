// src/datasource.ts
import { config } from 'dotenv';
import { DataSource } from 'typeorm';

config({ path: 'src/.env.development' });

export default new DataSource({
  type: 'postgres',
  host: process.env.DB_HOST,
  ssl: process.env.DB_SSL === 'true',
  port: Number(process.env.DB_PORT),
  username: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  logging: ['error', 'warn', 'query'],
  migrations: [
    process.env.NODE_ENV === 'production'
      ? 'dist/migrations/*.js'
      : 'src/migrations/*.ts',
  ],
  entities: [
    process.env.NODE_ENV === 'production'
      ? 'dist/**/*.entity.js'
      : 'src/**/*.entity.ts',
  ],
  synchronize: false,
});
