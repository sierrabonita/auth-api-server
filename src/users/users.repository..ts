import { User } from "@prisma/client";

export abstract class UsersRepository {
  abstract findById(id: string): Promise<User | null>;
  abstract findByEmail(email: string): Promise<User | null>;
  abstract createUser(params: {
    email: string;
    passwordHash: string;
    name?: string | null;
    role?: "user" | "admin";
  }): Promise<User>;
}
