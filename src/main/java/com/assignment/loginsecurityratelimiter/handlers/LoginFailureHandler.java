package com.assignment.loginsecurityratelimiter.handlers;

import com.assignment.loginsecurityratelimiter.service.LoginAttemptService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@RequiredArgsConstructor
public class LoginFailureHandler implements AuthenticationFailureHandler {

    private final LoginAttemptService loginAttemptService;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        String username = request.getParameter("username");
        String ip = request.getRemoteAddr();

        if (loginAttemptService.isBlocked(username, ip)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Too many failed attempts. Try again later.");
            return;
        }

        loginAttemptService.recordFailedAttempt(username, ip);

        if (exception instanceof BadCredentialsException) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid credentials.");
        } else {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Login failed.");
        }
    }
}
