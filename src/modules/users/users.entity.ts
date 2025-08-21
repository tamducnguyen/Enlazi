import {
  Column,
  Entity,
  JoinTable,
  ManyToMany,
  OneToMany,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { RoleEntity } from '../auth/role/roles.entity';
import { OAuthAccountEntity } from '../auth/oauth/oauth.entity';

@Entity('user')
export class UserEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;
  @Column({ unique: true })
  email: string;
  @Column()
  username: string;
  @Column({ type: 'varchar', select: false, nullable: true })
  hashedpassword: string | null | undefined;
  @Column({ default: true })
  isActive: boolean;
  @ManyToMany(() => RoleEntity, { eager: true })
  @JoinTable({ name: 'user_role' })
  roles: RoleEntity[];
  @OneToMany(() => OAuthAccountEntity, (oauthaccount) => oauthaccount.user)
  oauthAccounts: OAuthAccountEntity[];
}
