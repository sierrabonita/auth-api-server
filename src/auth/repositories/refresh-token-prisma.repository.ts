import { Injectable } from "@nestjs/common";
import type { RefreshToken } from "@prisma/client";
import { PrismaService } from "../../prisma/prisma.service";
import { RefreshTokenRepository } from "./refresh-token.repository";

@Injectable()
export class RefreshTokenPrismaRepository extends RefreshTokenRepository {
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  create(params: { userId: string; tokenHash: string; expiresAt: Date }): Promise<RefreshToken> {
    const { userId, tokenHash, expiresAt } = params;

    return this.prisma.refreshToken.create({
      data: {
        userId,
        tokenHash,
        expiresAt,
      },
    });
  }

  async findValidByUser(userId: string, now = new Date()): Promise<RefreshToken[]> {
    return this.prisma.refreshToken.findMany({
      where: {
        userId,
        revokedAt: null,
        expiresAt: { gt: now },
      },
      orderBy: {
        createdAt: "desc",
      },
    });
  }

  async findLatestValidByUser(userId: string, now = new Date()): Promise<RefreshToken | null> {
    return this.prisma.refreshToken.findFirst({
      where: {
        userId,
        revokedAt: null,
        expiresAt: { gt: now },
      },
      orderBy: {
        createdAt: "desc",
      },
    });
  }

  async revokeById(id: string, revokedAt = new Date()): Promise<void> {
    await this.prisma.refreshToken.update({
      where: {
        id,
      },
      data: {
        revokedAt,
      },
    });
  }

  async revokeAllForUser(userId: string, revokedAt = new Date()): Promise<number> {
    const res = await this.prisma.refreshToken.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt },
    });
    return res.count;
  }

  async deleteExpired(now = new Date()): Promise<number> {
    const res = await this.prisma.refreshToken.deleteMany({
      where: { expiresAt: { lte: now } },
    });

    return res.count;
  }
}
