import { Injectable, InternalServerErrorException } from "@nestjs/common";
import { PrismaService } from "../prisma/prisma.service";
import * as dotenv from 'dotenv'
import { MailtrapClient } from "mailtrap";
import { User } from "@prisma/client";
import { randomInt } from "crypto";
dotenv.config();

@Injectable()
export class CodeService {
    constructor(
        private readonly prisma: PrismaService
    ) { }

    genSixDigiCode(): string {

        const min = 0;
        const max = 999999;
        const randomNumber = randomInt(min, max + 1); // randomInt is exclusive of the upper bound
        return randomNumber.toString().padStart(6, '0');
    }

    // returns code;
    async sendNewEmailCode(user: User, code: string) {
        try {
            const TOKEN = process.env.MAILTRAP_API_TOKEN;

            const client = new MailtrapClient({
                token: TOKEN,
            });

            const sender = {
                email: "id@relearnapp.com",
                name: "ReLearn Account",
            };
            const recipients = [
                {
                    email: user.email,
                }
            ];

            await client
                .send({
                    from: sender,
                    to: recipients,
                    template_uuid: "bef99832-7ce1-43f0-ae74-08f295e6a8e2",
                    template_variables: {
                        "user_name": user.name,
                        "user_email": user.email,
                        "code": code,
                    }
                })
        } catch (error) {
            throw new InternalServerErrorException("An error occured sending the code.");
        }
    }

    async saveEmailCode(accountId: string, code: string) {
        try {
            await this.prisma.verificationCode.create({
                data: {
                    code: code,
                    type: "EMAIL",
                    account: {
                        connect: {
                            id: accountId
                        }
                    }
                }
            })
        } catch (error) {
            throw new InternalServerErrorException("An error occured saving the code");
        }
    }

    async removeAllCodes(accountId: string) {
        try {
            await this.prisma.verificationCode.deleteMany({
                where: {
                    accountId: accountId,
                }
            })
        } catch (error) {
            throw new InternalServerErrorException("An error occured removing previous codes.")
        }
    }

}