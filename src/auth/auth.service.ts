import { BadRequestException, Injectable, UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import * as bcrypt from "bcrypt";
import { UsersService } from "../users/users.service";
import { LoginDto } from "./dto/login.dto";
import { SignupDto } from "./dto/signup.dto";
import { RefreshTokenRepository } from "./repositories/refresh-token.repository";

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly refreshTokenRepository: RefreshTokenRepository,
    private readonly jwtService: JwtService,
    private readonly config: ConfigService,
  ) {}

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

    await this.refreshTokenRepository.revokeAllForUser(userId);
    return { success: true };
  }

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

    // 多セッション前提：全有効トークンから一致を探索
    const candidates = await this.refreshTokenRepository.findValidByUser(payload.sub);
    const matched = await this.findMatchingRecord(candidates, rawRefreshToken);
    if (!matched) throw new UnauthorizedException("Refresh token is not recognized");

    const user = await this.usersService.findById(payload.sub);
    if (!user) throw new UnauthorizedException("User no longer exists");

    // ローテーション：一致した旧RTを即失効
    await this.refreshTokenRepository.revokeById(matched.id);

    // 新発行＆保存
    const tokens = await this.issueTokens(user.id, user.email, user.role);
    await this.saveRefreshToken(user.id, tokens.refreshToken);

    return {
      user: { id: user.id, email: user.email, name: user.name, role: user.role },
      ...tokens,
    };
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

    await this.refreshTokenRepository.deleteExpired();

    const decoded = this.jwtService.decode(refreshToken) as { exp?: number };
    if (!decoded?.exp) return;

    const expiresAt = new Date(decoded.exp * 1000);
    await this.refreshTokenRepository.create({
      userId,
      tokenHash: hash,
      expiresAt,
    });
  }

  private async findMatchingRecord(
    records: { id: string; tokenHash: string }[],
    raw: string,
  ): Promise<{ id: string } | null> {
    for (const r of records) {
      if (await bcrypt.compare(raw, r.tokenHash)) return { id: r.id };
    }
    return null;
  }
}
