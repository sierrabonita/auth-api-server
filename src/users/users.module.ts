import { Module } from "@nestjs/common";
import { PrismaModule } from "../prisma/prisma.module";
import { UsersController } from "./users.controller";
import { UsersRepository } from "./users.repository.";
import { UsersService } from "./users.service";
import { UsersPrismaRepository } from "./users-prisma.repository";

@Module({
  imports: [PrismaModule],
  providers: [UsersService, { provide: UsersRepository, useClass: UsersPrismaRepository }],
  controllers: [UsersController],
  exports: [UsersService, UsersRepository],
})
export class UsersModule {}
