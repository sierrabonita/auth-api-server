import { BadRequestException, Injectable, UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import * as bcrypt from "bcrypt";
import { PrismaService } from "../prisma/prisma.service";
import { UsersService } from "../users/users.service";
import { LoginDto } from "./dto/login.dto";
import { SignupDto } from "./dto/signup.dto";

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly config: ConfigService,
  ) {}

  async refreshTokens(rawRefreshToken: string) {
    if (!rawRefreshToken) {
      throw new UnauthorizedException("Refresh token is required");
    }

    let payload: { sub: string; email: string; role: string };
    try {
      payload = await this.jwtService.verifyAsync(rawRefreshToken, {
        secret: this.getRefreshSecret(),
      });
    } catch {
      throw new UnauthorizedException("Invalid refresh token");
    }

    const tokenRecord = await this.prisma.refreshToken.findFirst({
      where: {
        userId: payload.sub,
        revokedAt: null,
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    if (!tokenRecord) {
      throw new UnauthorizedException("Invalid refresh token");
    }

    const matches = await bcrypt.compare(rawRefreshToken, tokenRecord.tokenHash);
    if (!matches) {
      throw new UnauthorizedException("Refresh token expired");
    }

    const user = await this.usersService.findById(payload.sub);
    if (!user) {
      throw new UnauthorizedException("User no longer exists");
    }

    const tokens = await this.issueTokens(user.id, user.email, user.role);
    await this.saveRefreshToken(user.id, tokens.refreshToken);

    return {
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
      ...tokens,
    };
  }

  async signup(dto: SignupDto) {
    const existing = await this.usersService.findByEmail(dto.email);
    if (existing) throw new BadRequestException("Email is already in use");

    const passwordHash = await bcrypt.hash(dto.password, 10);

    const user = await this.usersService.createUser({
      email: dto.email,
      passwordHash,
      name: dto.name,
    });

    const tokens = await this.issueTokens(user.id, user.email, user.role);
    await this.saveRefreshToken(user.id, tokens.refreshToken);

    return {
      user: { id: user.id, email: user.email, name: user.name, role: user.role },
      ...tokens,
    };
  }

  async login(dto: LoginDto) {
    const user = await this.usersService.findByEmail(dto.email);
    if (!user) throw new UnauthorizedException("Invalid credentials");

    const isValid = await bcrypt.compare(dto.password, user.passwordHash);
    if (!isValid) throw new UnauthorizedException("Invalid credentials");

    const tokens = await this.issueTokens(user.id, user.email, user.role);
    await this.saveRefreshToken(user.id, tokens.refreshToken);

    return {
      user: { id: user.id, email: user.email, name: user.name, role: user.role },
      ...tokens,
    };
  }

  async logout(userId: string) {
    if (!userId) {
      throw new BadRequestException("User id is required");
    }

    await this.prisma.refreshToken.updateMany({
      where: {
        userId,
        revokedAt: null,
      },
      data: {
        revokedAt: new Date(),
      },
    });

    return { success: true };
  }

  private getAccessSecret() {
    const s = this.config.get<string>("JWT_ACCESS_SECRET");
    if (!s) throw new Error("JWT_ACCESS_SECRET is not set");
    return s;
  }

  private getRefreshSecret() {
    const s = this.config.get<string>("JWT_REFRESH_SECRET");
    if (!s) throw new Error("JWT_REFRESH_SECRET is not set");
    return s;
  }

  private async issueTokens(userId: string, email: string, role: string) {
    const payload = { sub: userId, email, role };

    const accessSecret = this.getAccessSecret();
    const refreshSecret = this.getRefreshSecret();
    const accessExp = this.config.get("JWT_ACCESS_EXPIRES_IN") ?? "900s";
    const refreshExp = this.config.get("JWT_REFRESH_EXPIRES_IN") ?? "30d";

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: accessSecret,
        expiresIn: accessExp,
      }),
      this.jwtService.signAsync(payload, {
        secret: refreshSecret,
        expiresIn: refreshExp,
      }),
    ]);

    return { accessToken, refreshToken };
  }

  private async saveRefreshToken(userId: string, refreshToken: string) {
    const hash = await bcrypt.hash(refreshToken, 10);

    await this.prisma.refreshToken.deleteMany({
      where: { userId },
    });

    const decoded = this.jwtService.decode(refreshToken) as { exp?: number };
    if (!decoded?.exp) return;

    const expiresAt = new Date(decoded.exp * 1000);
    await this.prisma.refreshToken.create({
      data: {
        userId,
        tokenHash: hash,
        expiresAt,
      },
    });
  }
}
