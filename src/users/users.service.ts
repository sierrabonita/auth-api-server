import { Injectable } from "@nestjs/common";
import { Role } from "@prisma/client";
import { PrismaService } from "../prisma/prisma.service";

@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

  async createUser(params: { email: string; passwordHash: string; name?: string; role?: Role }) {
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

  async findByEmail(email: string) {
    return this.prisma.user.findUnique({
      where: { email },
    });
  }

  async findById(id: string) {
    return this.prisma.user.findUnique({
      where: { id },
    });
  }
}
