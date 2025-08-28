import { Role } from '../role/roles.enum';

export class Payload {
  constructor(roles: Role[], sub: string, email: string) {
    this.roles = roles;
    this.sub = sub;
    this.email = email;
  }
  roles: Role[];
  sub: string;
  email: string;
}
