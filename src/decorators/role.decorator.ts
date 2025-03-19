import { SetMetadata } from '@nestjs/common';
import { Role } from 'src/Roles/role.enum';

export const ROLE_KEY = 'roles'
const Roles = (...roles: Role[]) => SetMetadata(ROLE_KEY, roles);
console.log(Roles);

export {Roles}