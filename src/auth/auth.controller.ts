import { Body, Controller, Get, Post, Req, Res, UseGuards } from "@nestjs/common";
import type { Request, Response } from "express";
import { UsersService } from "../users/users.service";
import { AuthService } from "./auth.service";
import { CurrentUser } from "./decorators/current-user.decorator";
import { LoginDto } from "./dto/login.dto";
import { SignupDto } from "./dto/signup.dto";
import { JwtAuthGuard } from "./guards/jwt-auth.guard";

const REFRESH_TOKEN_COOKIE_NAME = "refresh_token";
@Controller("auth")
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly usersService: UsersService,
  ) {}

  // サインアップ
  @Post("signup")
  async signup(@Body() dto: SignupDto, @Res({ passthrough: true }) res: Response) {
    const { user, accessToken, refreshToken } = await this.authService.signup(dto);

    this.setRefreshTokenCookie(res, refreshToken);

    // クライアントには refreshToken を返さない（Cookie のみ）
    return {
      user,
      accessToken,
    };
  }

  // ログイン
  @Post("login")
  async login(@Body() dto: LoginDto, @Res({ passthrough: true }) res: Response) {
    const { user, accessToken, refreshToken } = await this.authService.login(dto);

    this.setRefreshTokenCookie(res, refreshToken);

    return {
      user,
      accessToken,
    };
  }

  // ログアウト
  @UseGuards(JwtAuthGuard)
  @Post("logout")
  async logout(@CurrentUser() user: { userId: string }, @Res({ passthrough: true }) res: Response) {
    // DB上のRefreshTokenを全部 revoke する（今の実装どおり）
    await this.authService.logout(user.userId);

    // Cookie を削除
    res.clearCookie(REFRESH_TOKEN_COOKIE_NAME, {
      path: "/auth/refresh",
    });

    return { success: true };
  }

  // トークンリフレッシュ
  @Post("refresh")
  async refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const refreshToken = req.cookies?.[REFRESH_TOKEN_COOKIE_NAME] || null;

    const {
      user,
      accessToken,
      refreshToken: newRefreshToken,
    } = await this.authService.refreshTokens(refreshToken);

    // 新しい Refresh Token でローテーション
    this.setRefreshTokenCookie(res, newRefreshToken);

    return {
      user,
      accessToken,
    };
  }

  // --- 自分の情報 ---
  @UseGuards(JwtAuthGuard)
  @Get("me")
  async me(@CurrentUser() user: { userId: string }) {
    return this.usersService.findById(user.userId);
  }

  private setRefreshTokenCookie(res: Response, token: string) {
    // 実運用なら env で secure や domain を切り替えるとよい
    res.cookie(REFRESH_TOKEN_COOKIE_NAME, token, {
      httpOnly: true,
      secure: false, // ローカル開発なら false、本番は true（HTTPS）
      sameSite: "lax",
      path: "/auth/refresh",
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30日
    });
  }
}
