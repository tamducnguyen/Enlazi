import {
  Column,
  Entity,
  JoinTable,
  ManyToMany,
  ManyToOne,
  OneToMany,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { RoleEntity } from '../../role/role.entity';
import { OAuthAccountEntity } from '../../auth/oauth/oauth.entity';
import { HobbyEntity } from './hobby.entity';
import { CefrLevelEntity } from './cefrlevel.entity';

@Entity('user')
export class UserEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;
  @Column({ unique: true, nullable: false })
  email: string;
  @Column({ nullable: false })
  username: string;
  @Column({ type: 'varchar', select: false, nullable: true })
  hashedpassword: string | null | undefined;
  @Column({ default: true })
  isActive: boolean;
  @ManyToMany(() => RoleEntity, { nullable: false })
  @JoinTable({ name: 'user_role' })
  roles: RoleEntity[];
  @OneToMany(() => OAuthAccountEntity, (oauthaccount) => oauthaccount.user, {
    nullable: true,
  })
  oauthAccounts: OAuthAccountEntity[];
  @ManyToOne(() => CefrLevelEntity, { nullable: true })
  cefrLevel: CefrLevelEntity;
  @ManyToMany(() => HobbyEntity, { nullable: true })
  @JoinTable({ name: 'user_hobby' })
  hobbies: HobbyEntity[];
}
