import type { RefreshToken } from "@prisma/client";

export abstract class RefreshTokenRepository {
  abstract create(params: {
    userId: string;
    tokenHash: string;
    expiresAt: Date;
  }): Promise<RefreshToken>;

  abstract findValidByUser(userId: string, now?: Date): Promise<RefreshToken[]>;

  abstract findLatestValidByUser(userId: string, now?: Date): Promise<RefreshToken | null>;

  abstract revokeById(id: string, revokedAt?: Date): Promise<void>;

  abstract revokeAllForUser(userId: string, revokedAt?: Date): Promise<number>;

  abstract deleteExpired(now?: Date): Promise<number>;
}
