import { Role } from '../enum/role.enum';

export class AuthUser {
  constructor(roles: Role[], sub: string, email: string) {
    this.roles = roles;
    this.sub = sub;
    this.email = email;
  }
  roles: Role[];
  sub: string;
  email: string;
}
