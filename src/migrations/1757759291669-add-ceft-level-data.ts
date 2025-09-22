import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddCeftLevelData1757759291669 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      INSERT INTO "cefr_level" ("name") VALUES 
        ('A1'),
        ('A2'),
        ('B1'),
        ('B2'),
        ('C1'),
        ('C2');
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DELETE FROM "cefr_level" WHERE "name" IN ('A1','A2','B1','B2','C1','C2 );`,
    );
  }
}
