/*

Code written 10/2024 - 2024 Finnean Carmichael / ReLearn

*/
import { Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { OAuth2Client } from 'google-auth-library';
import axios from 'axios';
import { JwtService } from '@nestjs/jwt';
import * as dotenv from 'dotenv';
import { PrismaService } from '../prisma/prisma.service';
import { UsersService } from '../users/users.service';
import { OauthProvider, User } from '@prisma/client';
import { v4 as uuidv4 } from 'uuid';
dotenv.config();

@Injectable()
export class AuthService {
    private client: OAuth2Client;

    constructor(
        private readonly jwtService: JwtService,
        private prisma: PrismaService,
        private readonly usersService: UsersService
    ) {
        this.client = new OAuth2Client(process.env.OAUTH_WEB_GOOGLE_CLIENT_ID, process.env.OAUTH_WEB_GOOGLE_CLIENT_SECRET);
    }

    async logout(refreshToken: string) {

        const storedRefreshToken = await this.usersService.findRefreshToken(refreshToken);
        if (!storedRefreshToken) {
            throw new UnauthorizedException('Invalid refresh token');
        }

        const userId = storedRefreshToken.userId;

        // Update the lastLogout timestamp to the current time
        await this.usersService.removeAllRefreshTokensForUser(userId);
        await this.usersService.updateLastLogout(userId)
    }

    async authenticateWithGoogle(idToken: string, accessToken: string) {
        // check if local account exists with same email.
        const userInfoResponse = await axios.get(
            'https://www.googleapis.com/oauth2/v3/userinfo',
            {
                headers: { Authorization: `Bearer ${accessToken}` },
            }
        );
        const userInfo = userInfoResponse.data;

        try {
            const query = await this.prisma.user.findFirst({
                where: {
                    AND: [
                        { email: userInfo.email },
                        {
                            account: {
                                loginSolution: "LOCAL"
                            }
                        }
                    ]
                }
            })
            if (query) throw new InternalServerErrorException("An account with this email already exists.")
        } catch (error) {
            throw new InternalServerErrorException(error.response.message);

        }
        try {
            // Verify the ID token
            const ticket = await this.client.verifyIdToken({
                idToken,
                audience: [
                    // have to include ios client id, as request originates from ios oauth app
                    process.env.OAUTH_IOS_GOOGLE_CLIENT_ID,
                    process.env.OAUTH_WEB_GOOGLE_CLIENT_ID,
                ],
            });
            // will throw error if fails & catch block will catch
            ticket.getPayload();

            // Fetch user info from Google using access token


            // Create or update user in the database
            try {
                // first check if account exists

                const query = await this.prisma.account.findFirst({
                    where: {
                        providerId: userInfo.sub,
                        oauthProvider: "GOOGLE"
                    },
                    include: { user: true }
                })

                // no result so create an account as user is new to platform.
                if (!query) {

                    const account = {
                        providerId: userInfo.sub as string,
                        email: (userInfo.email as string).toLowerCase(),
                        name: userInfo.name as string,
                        picture: userInfo.picture as string,
                        email_verified: userInfo.email_verified as boolean,
                        oauthProvider: "GOOGLE" as OauthProvider
                    }

                    await this.usersService.createOauthAccount(account)
                } else {
                    // account does exists and user model therefore should as well
                    // all we want to do is update the user account with latest data from oauth provider.
                    const userId = query.user[0].id;

                    const updatedUser: Partial<User> = { profileSnapshot: userInfo.picture, name: userInfo.name };

                    await this.usersService.updateUser(userId, updatedUser);

                    // remove any potential old refresh tokens for enhanced security
                    // & database hygiene.
                    // runs on every signin
                    await this.usersService.removeAllRefreshTokensForUser(userId)

                }

            } catch (error) {
                throw new Error(error.response.message)
            }

            const account = await this.prisma.account.findFirst({
                where: {
                    providerId: userInfo.sub,
                    oauthProvider: "GOOGLE"
                },
                include: { user: true }
            })
            // Issue your own JWT
            const jwtToken = this.jwtService.sign({ accountId: account.id });

            // create refreshtoken
            const refreshToken = uuidv4();

            // store new refreshtoken in db
            await this.usersService.createRefreshToken(account.user[0].id, refreshToken)

            return { jwtToken, user: account.user[0], refreshToken };
        } catch (error) {
            console.error('Error during Google authentication:', error);
            throw new Error(error.response.message);
        }
    }

    async refreshJwtToken(refreshToken: string) {
        try {
            //attempt to locate a refreshtoken already in the db
            const storedRefreshToken = await this.usersService.findRefreshToken(refreshToken);
            if (!storedRefreshToken || storedRefreshToken.revokedAt || new Date() > storedRefreshToken.expiresAt) {
                throw new UnauthorizedException("Invalid refresh token.");
            }

            const user = storedRefreshToken.user

            // rotate the refresh token
            const newRefreshToken = uuidv4();

            // revoke the old refreshtoken and save the newly rotated one
            await this.usersService.revokeRefreshToken(refreshToken, newRefreshToken);
            await this.usersService.createRefreshToken(user.id, newRefreshToken);

            // generate new jwt access token
            const jwtTokenPayload = { accountId: user.accountId };
            const newJwtToken = this.jwtService.sign(jwtTokenPayload);

            return { refreshToken: newRefreshToken, jwtToken: newJwtToken };
        } catch (error) {
            throw new UnauthorizedException('Could not refresh access token');

        }
    }

}
