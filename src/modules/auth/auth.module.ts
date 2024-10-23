/*

Code written 10/2024 - 2024 Finnean Carmichael / ReLearn

*/
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from 'src/controllers/auth/auth.controller';
import { AuthService } from 'src/services/auth/auth.service';
import { JwtStrategy } from 'src/strats/jwt.strategy';

import * as dotenv from 'dotenv';
import { PrismaService } from 'src/services/prisma/prisma.service';
import { UsersModule } from '../users/users.module';
import { LocalAuthController } from 'src/controllers/auth/localAuth.controller';
import { LocalAuthService } from 'src/services/auth/localAuth.service';
import { CodeService } from 'src/services/auth/code.service';
dotenv.config();

@Module({
    imports: [JwtModule.register({
        secret: process.env.RELEARN_JWT_SECRET, // Use environment variable in production
        signOptions: { expiresIn: process.env.RELEARN_JWT_EXPIRATION }, // Adjust token expiration as needed
    }), UsersModule],
    controllers: [AuthController, LocalAuthController],
    providers: [AuthService, JwtStrategy, PrismaService, LocalAuthService, CodeService],
})
export class AuthModule { }
