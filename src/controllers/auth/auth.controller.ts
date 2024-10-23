// src/auth/auth.controller.ts
import { Body, Controller, Get, Post, Req, Request, UnauthorizedException, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { JwtAuthGuard } from 'src/guards/jwt.guard';
import { AuthService } from 'src/services/auth/auth.service';

@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
    ) { }

    @Post('google')
    async googleAuthPost(
        @Body('idToken') idToken: string,
        @Body('accessToken') accessToken: string
    ) {
        const result = await this.authService.authenticateWithGoogle(idToken, accessToken);
        return result; // { user, jwtToken, refreshToken }
    }

    @UseGuards(JwtAuthGuard)
    @Post('validate-token')
    validateToken(@Request() req) {
        return { user: req.user };
    }

    @Post('logout')
    async logout(@Body('refreshToken') refreshToken) {


        await this.authService.logout(refreshToken);
        return { message: 'Successfully logged out' };
    }

    // refresh access token endpoint

    @Post('refresh-jwt-token')
    async refreshJwtToken(@Body('refreshToken') refreshToken: string) {
        if (!refreshToken) throw new UnauthorizedException("Refresh token is required.");
        // refresh token exists.
        const tokens = await this.authService.refreshJwtToken(refreshToken);
        return tokens; // { jwtToken, refreshToken }
    }
}
