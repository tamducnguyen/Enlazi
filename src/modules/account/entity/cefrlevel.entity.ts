import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';
import { CefrLevelEnum } from '../interface/cefr.enum';

@Entity('cefr_level')
export class CefrLevelEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;
  @Column({ type: 'enum', enum: CefrLevelEnum, unique: true, nullable: false })
  name: CefrLevelEnum;
}
