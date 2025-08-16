import {
  Column,
  Entity,
  JoinTable,
  ManyToMany,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { RoleEntity } from '../auth/role/roles.entity';

@Entity('user')
export class UserEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;
  @Column({ unique: true })
  email: string;
  @Column()
  username: string;
  @Column({ select: false })
  hashedpassword: string;
  @Column({ default: false })
  isVerified: boolean;
  @ManyToMany(() => RoleEntity, { eager: true })
  @JoinTable({ name: 'user_role' })
  roles: RoleEntity[];
}
