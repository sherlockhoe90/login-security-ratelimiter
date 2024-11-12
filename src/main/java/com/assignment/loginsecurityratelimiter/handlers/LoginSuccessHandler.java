package com.assignment.loginsecurityratelimiter.handlers;

import com.assignment.loginsecurityratelimiter.controller.AuthController;
import com.assignment.loginsecurityratelimiter.service.LoginAttemptService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@RequiredArgsConstructor
public class LoginSuccessHandler implements AuthenticationSuccessHandler {
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final LoginAttemptService loginAttemptService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        org.springframework.security.core.Authentication authentication)
            throws IOException {

        String username = request.getParameter("username");
        String ip = request.getRemoteAddr();

        loginAttemptService.resetAttempts(username, ip);
        logger.info("User {} from IP {} logged in successfully.", username, ip);
        response.sendRedirect("/api/v1.0/auth/home"); // redirect towards a protected endpoint/resource after a successful login
    }
}
