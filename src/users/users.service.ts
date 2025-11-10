import { Injectable } from "@nestjs/common";
import { Role, User } from "@prisma/client";
import { UsersRepository } from "./users.repository.";
@Injectable()
export class UsersService {
  constructor(private readonly usersRepository: UsersRepository) {}

  createUser(params: {
    email: string;
    passwordHash: string;
    name?: string;
    role?: Role;
  }): Promise<User> {
    return this.usersRepository.createUser(params);
  }

  findByEmail(email: string): Promise<User | null> {
    return this.usersRepository.findByEmail(email);
  }

  findById(id: string): Promise<User | null> {
    return this.usersRepository.findById(id);
  }
}
