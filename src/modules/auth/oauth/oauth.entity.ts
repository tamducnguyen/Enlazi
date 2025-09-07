import {
  Column,
  Entity,
  JoinColumn,
  PrimaryGeneratedColumn,
  Index,
  ManyToOne,
} from 'typeorm';
import { Provider } from './provider.enum';
import { UserEntity } from 'src/modules/account/entity/user.entity';
@Entity({ name: 'oauth_account' })
@Index(['provider', 'providerAccountId'], { unique: true })
@Index(['user', 'provider'], { unique: true })
export class OAuthAccountEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;
  @ManyToOne(() => UserEntity, (u) => u.oauthAccounts, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'user_id' })
  user: UserEntity;
  @Column({ nullable: false, type: 'enum', enum: Provider })
  provider: Provider;
  @Column({ nullable: false })
  providerAccountId: string;
}
