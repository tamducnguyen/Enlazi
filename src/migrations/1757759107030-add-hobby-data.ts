import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddHobbyData1757759107030 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      INSERT INTO "hobby" ("name") VALUES 
        ('sport'),
        ('technology'),
        ('travel'),
        ('game'),
        ('business');
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DELETE FROM "role" WHERE "name" IN ('sport','technology','travel','game','business' );`,
    );
  }
}
