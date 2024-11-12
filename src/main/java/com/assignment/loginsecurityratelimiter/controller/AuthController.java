package com.assignment.loginsecurityratelimiter.controller;

import com.assignment.loginsecurityratelimiter.service.LoginAttemptService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/v1.0/auth")
@RequiredArgsConstructor
public class AuthController {
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthenticationManager authenticationManager;
    private final LoginAttemptService loginAttemptService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestParam String username, @RequestParam String password, HttpServletRequest request) {
        //getting the user's IP address
        String ipAddress = request.getRemoteAddr();

        //checking if the login attempts have exceeded threshold for this username+IP address combination
        if (loginAttemptService.isBlocked(username, ipAddress)) {
            logger.warn("Blocked login attempt for user {} from IP {}. Too many failed attempts.", username, ipAddress);
            return ResponseEntity.status(429).body("Login attempts exceeded. Please try again later.");
        }

        try {
            // attempt to authenticate the user with the provided username and password
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );

            // set the authentication context upon a successful login
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // reset the login attempt counter upon a successful login
            loginAttemptService.resetAttempts(username, ipAddress);
            logger.info("Successful login for user {} from IP {}. Attempt counts reset.", username, ipAddress);
            return ResponseEntity.ok("Login successful.");

        } catch (Exception e) {
            // if authentication fails, record the failed attempt and handle rate-limiting
            logger.error("Authentication failed for user {} from IP {}.", username, ipAddress);
            loginAttemptService.recordFailedAttempt(username, ipAddress);
            return ResponseEntity.status(401).body("Invalid credentials");
        }
    }
}
