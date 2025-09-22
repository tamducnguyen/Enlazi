import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddRoleData1757758584776 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      INSERT INTO "role" ("name") VALUES 
        ('admin'),
        ('teacher'),
        ('student');
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DELETE FROM "role" WHERE "name" IN ('admin','teacher','student');`,
    );
  }
}
