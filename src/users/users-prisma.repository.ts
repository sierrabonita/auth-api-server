import { Injectable } from "@nestjs/common";
import { Role, User } from "@prisma/client";
import { PrismaService } from "../prisma/prisma.service";
import { UsersRepository } from "./users.repository.";

@Injectable()
export class UsersPrismaRepository extends UsersRepository {
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  findByEmail(email: string): Promise<User | null> {
    return this.prisma.user.findUnique({
      where: { email },
    });
  }

  findById(id: string): Promise<User | null> {
    return this.prisma.user.findUnique({
      where: { id },
    });
  }

  createUser(params: {
    email: string;
    passwordHash: string;
    name?: string | null;
    role?: Role;
  }): Promise<User> {
    const { email, passwordHash, name, role } = params;
    return this.prisma.user.create({
      data: {
        email,
        passwordHash,
        name,
        role: role ?? "user",
      },
    });
  }
}
