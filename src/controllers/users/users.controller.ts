import { Controller, Get, Request, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from 'src/guards/jwt.guard';
import { UsersService } from 'src/services/users/users.service';
import { TypedRequest } from 'src/types';

@Controller('user')
export class UsersController {
    constructor(
        private readonly userService: UsersService
    ) { }
    @UseGuards(JwtAuthGuard)
    @Get('/')
    userRes(@Request() req) {
        return { user: req.user }
    }

    @UseGuards(JwtAuthGuard)
    @Get('/signupstate')
    async userSignupState(@Request() req) {
        const hasCompletedSignup = await this.userService.hasCompletedSignup(req.user.id);
        return { state: hasCompletedSignup };
    }

    @UseGuards(JwtAuthGuard)
    @Get('/preflight/verify')
    async passedChecks(@Request() req) {
        const result = await this.userService.passedPreflightChecks(req.user.id);
        return result;
    }

}
