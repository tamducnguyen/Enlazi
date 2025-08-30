import { Column, Entity, PrimaryGeneratedColumn, ManyToMany } from 'typeorm';
import { Role } from './roles.enum';
import { UserEntity } from 'src/modules/users/users.entity';

@Entity('role')
export class RoleEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;
  @Column({ type: 'enum', enum: Role, unique: true })
  name: Role;
  @ManyToMany(() => UserEntity, (u) => u.roles)
  users: UserEntity[];
}
