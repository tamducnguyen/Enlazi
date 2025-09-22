import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreatTables1757758454483 implements MigrationInterface {
  name = 'CreatTables1757758454483';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TYPE "public"."role_name_enum" AS ENUM('student', 'admin', 'teacher')`,
    );
    await queryRunner.query(
      `CREATE TABLE "role" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "name" "public"."role_name_enum" NOT NULL, CONSTRAINT "UQ_ae4578dcaed5adff96595e61660" UNIQUE ("name"), CONSTRAINT "PK_b36bcfe02fc8de3c57a8b2391c2" PRIMARY KEY ("id"))`,
    );
    await queryRunner.query(
      `CREATE TYPE "public"."oauth_account_provider_enum" AS ENUM('google', 'credential')`,
    );
    await queryRunner.query(
      `CREATE TABLE "oauth_account" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "provider" "public"."oauth_account_provider_enum" NOT NULL, "providerAccountId" character varying NOT NULL, "user_id" uuid, CONSTRAINT "PK_01ec7d2a8273dcaaed3dd10a4fb" PRIMARY KEY ("id"))`,
    );
    await queryRunner.query(
      `CREATE UNIQUE INDEX "IDX_90ee56654328a01c671fdff2a2" ON "oauth_account" ("user_id", "provider") `,
    );
    await queryRunner.query(
      `CREATE UNIQUE INDEX "IDX_2fee1aefe3f04645282ab41936" ON "oauth_account" ("provider", "providerAccountId") `,
    );
    await queryRunner.query(
      `CREATE TABLE "hobby" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "name" character varying NOT NULL, CONSTRAINT "UQ_3ec51a58ecde5e69732ed079ede" UNIQUE ("name"), CONSTRAINT "PK_9cf21d5206ec584a4cc14a8703e" PRIMARY KEY ("id"))`,
    );
    await queryRunner.query(
      `CREATE TYPE "public"."cefr_level_name_enum" AS ENUM('A1', 'A2', 'B1', 'B2', 'C1', 'C2')`,
    );
    await queryRunner.query(
      `CREATE TABLE "cefr_level" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "name" "public"."cefr_level_name_enum" NOT NULL, CONSTRAINT "UQ_9401b2ece54a522137c929192bd" UNIQUE ("name"), CONSTRAINT "PK_9b6e563a4018b419be2613d76b9" PRIMARY KEY ("id"))`,
    );
    await queryRunner.query(
      `CREATE TABLE "user" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "email" character varying NOT NULL, "username" character varying NOT NULL, "hashedpassword" character varying, "isActive" boolean NOT NULL DEFAULT true, "cefrLevelId" uuid, CONSTRAINT "UQ_e12875dfb3b1d92d7d7c5377e22" UNIQUE ("email"), CONSTRAINT "PK_cace4a159ff9f2512dd42373760" PRIMARY KEY ("id"))`,
    );
    await queryRunner.query(
      `CREATE TABLE "refresh_token" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "tokenHash" character varying NOT NULL, "sessionId" uuid NOT NULL, "isRevoked" boolean NOT NULL DEFAULT false, "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "expiresAt" TIMESTAMP NOT NULL, "userId" uuid, CONSTRAINT "PK_b575dd3c21fb0831013c909e7fe" PRIMARY KEY ("id"))`,
    );
    await queryRunner.query(
      `CREATE TABLE "user_role" ("userId" uuid NOT NULL, "roleId" uuid NOT NULL, CONSTRAINT "PK_7b4e17a669299579dfa55a3fc35" PRIMARY KEY ("userId", "roleId"))`,
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_ab40a6f0cd7d3ebfcce082131f" ON "user_role" ("userId") `,
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_dba55ed826ef26b5b22bd39409" ON "user_role" ("roleId") `,
    );
    await queryRunner.query(
      `CREATE TABLE "user_hobby" ("userId" uuid NOT NULL, "hobbyId" uuid NOT NULL, CONSTRAINT "PK_6e0ef98b061bb9a2b46b433cccc" PRIMARY KEY ("userId", "hobbyId"))`,
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_eb0343ec2bfba4f0d2ffc63158" ON "user_hobby" ("userId") `,
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_b2243d7c165f1c51ccb1cd29ce" ON "user_hobby" ("hobbyId") `,
    );
    await queryRunner.query(
      `ALTER TABLE "oauth_account" ADD CONSTRAINT "FK_e355ddb0b69b083cbf253345d1c" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE NO ACTION`,
    );
    await queryRunner.query(
      `ALTER TABLE "user" ADD CONSTRAINT "FK_bd740d1c9010b9c57693d1c00e0" FOREIGN KEY ("cefrLevelId") REFERENCES "cefr_level"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`,
    );
    await queryRunner.query(
      `ALTER TABLE "refresh_token" ADD CONSTRAINT "FK_8e913e288156c133999341156ad" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE NO ACTION`,
    );
    await queryRunner.query(
      `ALTER TABLE "user_role" ADD CONSTRAINT "FK_ab40a6f0cd7d3ebfcce082131fd" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE`,
    );
    await queryRunner.query(
      `ALTER TABLE "user_role" ADD CONSTRAINT "FK_dba55ed826ef26b5b22bd39409b" FOREIGN KEY ("roleId") REFERENCES "role"("id") ON DELETE CASCADE ON UPDATE CASCADE`,
    );
    await queryRunner.query(
      `ALTER TABLE "user_hobby" ADD CONSTRAINT "FK_eb0343ec2bfba4f0d2ffc631581" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE`,
    );
    await queryRunner.query(
      `ALTER TABLE "user_hobby" ADD CONSTRAINT "FK_b2243d7c165f1c51ccb1cd29cee" FOREIGN KEY ("hobbyId") REFERENCES "hobby"("id") ON DELETE CASCADE ON UPDATE CASCADE`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "user_hobby" DROP CONSTRAINT "FK_b2243d7c165f1c51ccb1cd29cee"`,
    );
    await queryRunner.query(
      `ALTER TABLE "user_hobby" DROP CONSTRAINT "FK_eb0343ec2bfba4f0d2ffc631581"`,
    );
    await queryRunner.query(
      `ALTER TABLE "user_role" DROP CONSTRAINT "FK_dba55ed826ef26b5b22bd39409b"`,
    );
    await queryRunner.query(
      `ALTER TABLE "user_role" DROP CONSTRAINT "FK_ab40a6f0cd7d3ebfcce082131fd"`,
    );
    await queryRunner.query(
      `ALTER TABLE "refresh_token" DROP CONSTRAINT "FK_8e913e288156c133999341156ad"`,
    );
    await queryRunner.query(
      `ALTER TABLE "user" DROP CONSTRAINT "FK_bd740d1c9010b9c57693d1c00e0"`,
    );
    await queryRunner.query(
      `ALTER TABLE "oauth_account" DROP CONSTRAINT "FK_e355ddb0b69b083cbf253345d1c"`,
    );
    await queryRunner.query(
      `DROP INDEX "public"."IDX_b2243d7c165f1c51ccb1cd29ce"`,
    );
    await queryRunner.query(
      `DROP INDEX "public"."IDX_eb0343ec2bfba4f0d2ffc63158"`,
    );
    await queryRunner.query(`DROP TABLE "user_hobby"`);
    await queryRunner.query(
      `DROP INDEX "public"."IDX_dba55ed826ef26b5b22bd39409"`,
    );
    await queryRunner.query(
      `DROP INDEX "public"."IDX_ab40a6f0cd7d3ebfcce082131f"`,
    );
    await queryRunner.query(`DROP TABLE "user_role"`);
    await queryRunner.query(`DROP TABLE "refresh_token"`);
    await queryRunner.query(`DROP TABLE "user"`);
    await queryRunner.query(`DROP TABLE "cefr_level"`);
    await queryRunner.query(`DROP TYPE "public"."cefr_level_name_enum"`);
    await queryRunner.query(`DROP TABLE "hobby"`);
    await queryRunner.query(
      `DROP INDEX "public"."IDX_2fee1aefe3f04645282ab41936"`,
    );
    await queryRunner.query(
      `DROP INDEX "public"."IDX_90ee56654328a01c671fdff2a2"`,
    );
    await queryRunner.query(`DROP TABLE "oauth_account"`);
    await queryRunner.query(`DROP TYPE "public"."oauth_account_provider_enum"`);
    await queryRunner.query(`DROP TABLE "role"`);
    await queryRunner.query(`DROP TYPE "public"."role_name_enum"`);
  }
}
