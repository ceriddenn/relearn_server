import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { Account, OauthProvider, Prisma, RefreshToken, User } from '@prisma/client';
import { addDays } from 'date-fns';
import { PrismaService } from 'src/services/prisma/prisma.service';
import * as dotenv from 'dotenv';
dotenv.config();
type RefreshTokenWithUser = Prisma.RefreshTokenGetPayload<{ include: { user: true } }>

type AccountWithUser = Prisma.AccountGetPayload<{ include: { user: true } }>;

@Injectable()
export class UsersService {
    constructor(private prisma: PrismaService) { }

    async findByEmail(email: string): Promise<User | null> {
        return await this.prisma.user.findUnique({
            where: {
                email: email,
            }
        })
    }

    async findById(userId: string): Promise<User | null> {
        return await this.prisma.user.findUnique({
            where: { id: userId },
            include: { refreshTokens: true },
        });
    }

    async findByAccountId(accountId: string): Promise<User | null> {
        return await this.prisma.user.findFirst({
            where: {
                accountId: accountId,
            }
        })
    }

    async findByProvidereId(providerId: string): Promise<User | null> {
        return await this.prisma.user.findFirst({
            where: {
                account: {
                    providerId,
                }
            },
            include: { refreshTokens: true },
        });
    }

    async createLocalAccount(data: {
        email: string;
        hashedPassword: string;
        name: string;

    }): Promise<AccountWithUser> {

        const defaultProfileIcon = "https://static-00.iconduck.com/assets.00/profile-circle-icon-256x256-cm91gqm2.png";
        try {
            const account = await this.prisma.account.create({
                data: {
                    localCredentials: {
                        create: {
                            email: data.email.toLowerCase(),
                            password: data.hashedPassword
                        }
                    },
                    loginSolution: "LOCAL",
                    user: {
                        create: {
                            email: data.email.toLowerCase(),
                            emailVerified: false,
                            profileSnapshot: defaultProfileIcon,
                            name: data.name,

                        }
                    }
                },
                include: {
                    user: true
                }
            })
            return account;

        } catch (error) {
            console.log(error)
            throw new InternalServerErrorException("An error occured signing up. Please try again.")
        }

    }

    async createOauthAccount(data: {
        providerId: string;
        email: string;
        name: string;
        picture?: string;
        email_verified?: boolean;
        oauthProvider: OauthProvider
    }): Promise<Account> {
        return await this.prisma.account.create({
            data: {
                loginSolution: "OAUTH",
                providerId: data.providerId,
                oauthProvider: data.oauthProvider,
                user: {
                    create: {
                        profileSnapshot: data.picture,
                        name: data.name,
                        email: data.email.toLowerCase(),
                        emailVerified: data.email_verified
                    }
                }
            }
        })
    }

    async passedPreflightChecks(userId: string): Promise<{ passed: boolean, message: string }> {
        const user = await this.prisma.user.findFirst({
            where: {
                id: userId
            },
            include: {
                account: true
            }
        })

        // if user logged in with no oauth and never verified email, denied
        if (!user.emailVerified && user.account.loginSolution == "LOCAL") return { passed: false, message: "Please verify your email." }

        // if user logged in with phone and never set it then denied
        if (user.account.loginSolution == "SMS" && user.phone.length == 0) return { passed: false, message: "Please confirm your phone." }

        return { passed: true, message: "All verification methods are verified." }
    }

    async updateUser(userId: string, data: Partial<User>): Promise<User> {
        return await this.prisma.user.update({
            where: { id: userId },
            data,
        });
    }

    async updateLastLogout(userId: string): Promise<void> {
        await this.prisma.user.update({
            where: { id: userId },
            data: {
                account: {
                    update: {
                        lastLogout: new Date()
                    }
                }
            },
        });
    }

    // Refresh Token Methods

    async createRefreshToken(userId: string, token: string): Promise<RefreshToken> {
        return await this.prisma.refreshToken.create({
            data: {
                token,
                expiresAt: addDays(new Date(), Number.parseInt(process.env.RELEARN_REFRESH_TOKEN_EXPIRATION)),
                user: { connect: { id: userId } },
            },
        });
    }

    async revokeRefreshToken(token: string, replacedByToken?: string): Promise<void> {
        await this.prisma.refreshToken.update({
            where: { token },
            data: {
                revokedAt: new Date(),
                replacedByToken: replacedByToken ?? null,
            },
        });
    }

    async findRefreshToken(token: string): Promise<RefreshTokenWithUser | null> {
        return await this.prisma.refreshToken.findUnique({
            where: { token },
            include: { user: true }
        });
    }

    async removeAllRefreshTokensForUser(userId: string): Promise<void> {
        console.log(userId)
        await this.prisma.refreshToken.deleteMany({
            where: {
                user: {
                    id: userId
                }
            },
        });
    }

    async hasCompletedSignup(userId: string): Promise<boolean> {
        const user = await this.prisma.user.findFirst({
            where: {
                id: userId,
            },
        })
        return user.signupComplete;
    }
}

