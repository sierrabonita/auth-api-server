import { Module } from "@nestjs/common";
import { JwtModule } from "@nestjs/jwt";
import { PassportModule } from "@nestjs/passport";
import { PrismaModule } from "../prisma/prisma.module";
import { UsersModule } from "../users/users.module";
import { AuthController } from "./auth.controller";
import { AuthService } from "./auth.service";
import { RefreshTokenRepository } from "./repositories/refresh-token.repository";
import { RefreshTokenPrismaRepository } from "./repositories/refresh-token-prisma.repository";
import { JwtStrategy } from "./strategies/jwt.strategy";
@Module({
  imports: [UsersModule, PrismaModule, PassportModule, JwtModule.register({})],
  providers: [
    AuthService,
    JwtStrategy,
    { provide: RefreshTokenRepository, useClass: RefreshTokenPrismaRepository },
  ],
  controllers: [AuthController],
  exports: [AuthService, RefreshTokenRepository],
})
export class AuthModule {}
