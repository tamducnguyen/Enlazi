import { UserEntity } from 'src/modules/users/users.entity';
import {
  Column,
  CreateDateColumn,
  Entity,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';

@Entity('refresh_token')
export class RefreshTokenEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;
  @ManyToOne(() => UserEntity, { onDelete: 'CASCADE' })
  user: UserEntity;
  @Column()
  tokenHash: string;
  @Column({ type: 'uuid' })
  sessionId: string;
  @Column({ default: false })
  isRevoked: boolean;
  @CreateDateColumn()
  createdAt: Date;
  @Column()
  expiresAt: Date;
}
