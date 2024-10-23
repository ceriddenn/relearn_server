/*

Code written 10/2024 - 2024 Finnean Carmichael / ReLearn

*/
import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as dotenv from 'dotenv';
import { PrismaService } from '../prisma/prisma.service';
import { UsersService } from '../users/users.service';
import * as EmailValidator from 'email-validator';
import * as bcrypt from 'bcrypt'
import { v4 as uuidv4 } from 'uuid';
import { User } from '@prisma/client';
import { CodeService } from './code.service';

dotenv.config();

@Injectable()
export class LocalAuthService {
    constructor(
        private readonly jwtService: JwtService,
        private prisma: PrismaService,
        private readonly codeService: CodeService,
        private readonly usersService: UsersService
    ) { }

    async completeSignup(userId: string, username: string) {
        try {
            // check if username is available
            const query = await this.prisma.user.findFirst({
                where: {
                    username: username,
                }
            })

            if (query) throw new InternalServerErrorException("This username is taken!")


            await this.prisma.user.update({
                where: {
                    id: userId,
                },
                data: {
                    username: username,
                    signupComplete: true,
                }
            })
        } catch (error) {
            throw new InternalServerErrorException(error.response.message)
        }
    }

    async verifyEmail(accountId: string, code: string) {
        try {
            // first check if codes match with provided accountId
            const query = await this.prisma.verificationCode.findFirst({
                where: {
                    AND: [
                        {
                            code: code,
                        },
                        {
                            accountId: accountId
                        }
                    ]
                }
            })
            console.log(query)
            console.log(accountId)
            console.log(code);
            if (!query) throw new InternalServerErrorException("The provided code does not match.");

            // if exists then remove all codes and set email_verified to true
            await this.codeService.removeAllCodes(accountId);
            const user = await this.usersService.findByAccountId(accountId);
            await this.prisma.user.update({
                where: {
                    id: user.id,
                },
                data: {
                    emailVerified: true,
                }
            })

        } catch (error) {
            throw new InternalServerErrorException(error.response.message)
        }
    }

    async sendVerificationEmail(user: User) {
        await this.codeService.removeAllCodes(user.accountId);
        const code = this.codeService.genSixDigiCode();
        // save the code.
        await this.codeService.saveEmailCode(user.accountId, code);
        // then send the code to user.
        await this.codeService.sendNewEmailCode(user, code);
    }

    async isEmailAvailable(email: string): Promise<boolean> {

        if (!email) return true;

        try {
            const query = await this.prisma.user.findUnique({
                where: {
                    email: email.toLowerCase(),
                }
            })

            if (!query) return true
            if (query) return false;

            throw new InternalServerErrorException("An edge case error occured. Please try again")
        } catch (error) {
            throw new InternalServerErrorException("The request failed.")
        }

    }

    async isEmailValid(email: string): Promise<boolean> {
        if (!email) return false;

        if (EmailValidator.validate(email)) return true;
        return false;
    }

    async authenticateLocalCredentials(email: string, password: string) {
        // first check if user exists.
        try {
            const account = await this.prisma.account.findFirst({
                where: {
                    localCredentialsEmail: email.toLowerCase(),
                },
                include: {
                    localCredentials: true,
                    user: true,
                }
            })

            if (!account) throw new NotFoundException("No account was found with the provided email.");

            // an account exists
            // compare credentials with hashed and confirm passwords match signatures
            const hashedPassword = account.localCredentials.password;
            const matchQ = await bcrypt.compare(password, hashedPassword);

            // passwords did not match so throw
            if (!matchQ) throw new NotFoundException("The credentials provided did not match an account stored on our server.");

            // password did match so generate necessary auth tokens (refresh, jwt access);

            // signing new access token with payload obj
            const jwtToken = this.jwtService.sign({ accountId: account.id });

            // remove any possible old refresh tokens for enhanced security
            await this.usersService.removeAllRefreshTokensForUser(account.user[0].id);

            // generate new refresh token for this session
            const refreshToken = uuidv4();

            // store the token in the db
            await this.usersService.createRefreshToken(account.user[0].id, refreshToken);

            // return tokens
            return { jwtToken, refreshToken }

        } catch (error) {
            console.log(error)
            throw new InternalServerErrorException(error.response.message)
        }
    }

    async signUpUser(email: string, name: string, password: string, tos: boolean) {
        if (!tos) throw new InternalServerErrorException("Please accept the TOS.")
        // all fields *should* exist due to check in controller

        /* already verified email is unique therefore no query to see
            if account already exists is necessary */
        const saltRounds = 10
        try {
            const genedSalt = await bcrypt.genSalt(saltRounds);

            const hashedPassword = await bcrypt.hash(password, genedSalt);

            const data = {
                email: email.toLowerCase(),
                name: name,
                hashedPassword: hashedPassword,
            }

            const account = await this.usersService.createLocalAccount(data)

            // assign user a refresh token and a jwt access token.

            // creating a refresh token
            const refreshToken = uuidv4();

            // creating the access token with acc id as payload
            const jwtToken = this.jwtService.sign({ accountId: account.id });

            await this.usersService.createRefreshToken(account.user[0].id, refreshToken)
            return { jwtToken, refreshToken };

        } catch (error) {
            console.log(error);
        }

    }

}