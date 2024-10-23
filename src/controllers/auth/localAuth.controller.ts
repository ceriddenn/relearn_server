import { Body, Controller, Get, InternalServerErrorException, Post, Request, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from 'src/guards/jwt.guard';
import { LocalAuthService } from 'src/services/auth/localAuth.service';
import { MailtrapClient } from 'mailtrap'
import { User } from '@prisma/client';
import { UsersService } from 'src/services/users/users.service';
@Controller('auth/local')
export class LocalAuthController {
    constructor(
        private readonly localAuthService: LocalAuthService,
        private readonly usersService: UsersService,
    ) { }

    @UseGuards(JwtAuthGuard)
    @Post('/complete-signup')
    async completeSignup(@Request() req, @Body('username') username) {
        if (!username) throw new InternalServerErrorException("No username provided. Please provide a username with your request.");
        if (req.user.signupComplete) throw new InternalServerErrorException("You have already completed signup.")
        await this.localAuthService.completeSignup(req.user.id, username);

        return { message: "Successfully completed signup.", status: 200 };
    }

    @Post('/identifier/available')
    async isEmailAvailable(@Body('email') email) {
        const isAvailable = await this.localAuthService.isEmailAvailable(email);

        const isValid = await this.localAuthService.isEmailValid(email);

        return { isAvailable: isAvailable, isValid: isValid }
    }

    @UseGuards(JwtAuthGuard)
    @Post('/identifier/verify')
    async verifyEmail(@Request() req, @Body('code') code) {
        if (!code) throw new InternalServerErrorException("No code provided. Please provide a code with your request.");
        const user = req.user as User;
        await this.localAuthService.verifyEmail(user.accountId, code)
        return { message: "Successfully sent the code.", status: 200 };
    }

    @Post('/authenticate')
    async signinLocalAccount(@Body('email') email, @Body('password') password) {
        if (!email || !password) throw new InternalServerErrorException("Please provide an email and password.");

        // attempt to login user, will handle checking if user exists and all other error handling;
        const tokens = await this.localAuthService.authenticateLocalCredentials(email, password);

        return tokens;
    }

    @Post('/signup')
    async signupLocalAccount(@Body('name') name, @Body('email') email, @Body('password') password, @Body('tos') tos) {
        if (!email || !name || !email) throw new InternalServerErrorException("Please provide a name, email, and password.");
        // first verify email is valid & avail on server side.
        const isAvailable = await this.localAuthService.isEmailAvailable(email);
        const isValid = await this.localAuthService.isEmailValid(email);

        // these also prevent a user who has logged in with oauth to create a local account
        // with an email which is from the same provider.

        if (!isValid) throw new InternalServerErrorException("The email provided is invalid.");
        if (!isAvailable) throw new InternalServerErrorException("The email provided is already in use by another account.");

        // attempt to signup the user.
        const tokens = await this.localAuthService.signUpUser(email, name, password, tos);

        // if success, then send verification code
        // first get full user object
        const user = await this.usersService.findByEmail(email);
        await this.localAuthService.sendVerificationEmail(user)

        return tokens;

    }


}
