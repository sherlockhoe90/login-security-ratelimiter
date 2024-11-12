package com.assignment.loginsecurityratelimiter;

import com.assignment.loginsecurityratelimiter.service.LoginAttemptService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class LoginSecurityRatelimiterApplicationTests {

    @Autowired
    private MockMvc mockMvc;
    @MockBean
    private LoginAttemptService rateLimiterService;
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private Authentication authentication;
    @Mock
    private Logger logger;

    private final String username = "user";
    private final String password = "password";
    private final String invalidPassword = "wrongpassword";
    private final String ipAddress = "127.0.0.1"; //localhost (subject to change)

    @BeforeEach
    public void setUp() {
        //setting default behavior for rate limiting and authentication
        when(rateLimiterService.isBlocked(anyString(), anyString())).thenReturn(false);
        doNothing().when(rateLimiterService).recordFailedAttempt(anyString(), anyString());
        doNothing().when(rateLimiterService).resetAttempts(anyString(), anyString());
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void contextLoads() {
    }

    //test case: successful login
    @Test
    public void testSuccessfulLogin() throws Exception {
        when(authenticationManager.authenticate(any())).thenReturn(authentication);

        mockMvc.perform(post("/api/v1.0/auth/login")
                        .param("username", username)
                        .param("password", password))
                .andExpect(status().isOk())
                .andExpect(content().string("Login successful."));

        //verifying that attempts get reset after a successful login
        verify(rateLimiterService, times(1)).resetAttempts(username, ipAddress);
    }

    //test case: failed login by invalid credentials
    @Test
    public void testInvalidLogin() throws Exception {
        when(authenticationManager.authenticate(any()))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        mockMvc.perform(post("/api/v1.0/auth/login")
                        .param("username", username)
                        .param("password", invalidPassword))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Invalid credentials"));

        //verifying that attempt count is incremented on a failed login
        verify(rateLimiterService, times(1)).recordFailedAttempt(username, ipAddress);
    }

    //test case: exceeding the rate limit threshold after the specified amount of failed attempts
    @Test
    public void testRateLimitExceeded() throws Exception {
        //set up rate limiter to simulate exceeding limit
        //test if it is blocked
        when(rateLimiterService.isBlocked(username, ipAddress)).thenReturn(true);

        mockMvc.perform(post("/api/v1.0/auth/login")
                        .param("username", username)
                        .param("password", invalidPassword))
                .andExpect(status().isTooManyRequests())
                .andExpect(content().string("Login attempts exceeded. Please try again later."));

        //verifying that number of attempts incremented when rate limit is exceeded
        verify(rateLimiterService, never()).recordFailedAttempt(username, ipAddress);
    }

    //test case: rate limiting resets after successful login
    @Test
    public void testRateLimitResetAfterSuccessfulLogin() throws Exception {
        when(authenticationManager.authenticate(any())).thenReturn(authentication);
        when(rateLimiterService.isBlocked(username, ipAddress)).thenReturn(false);

        //performing login after being rate-limited and successfully authenticate
        mockMvc.perform(post("/api/v1.0/auth/login")
                        .param("username", username)
                        .param("password", password))
                .andExpect(status().isOk())
                .andExpect(content().string("Login successful."));

        //verifying that the rate limiter is reset on successful login
        verify(rateLimiterService, times(1)).resetAttempts(username, ipAddress);
    }

    //test case: multiple failed logins and then a successful login
    @Test
    public void testMultipleFailedAttemptsThenSuccess() throws Exception {
        when(authenticationManager.authenticate(any()))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        //simulating failed login attempts up to the threshold
        for (int i = 0; i < 4; i++) {
            mockMvc.perform(post("/api/v1.0/auth/login")
                            .param("username", username)
                            .param("password", invalidPassword))
                    .andExpect(status().isUnauthorized())
                    .andExpect(content().string("Invalid credentials"));
            verify(rateLimiterService, times(i + 1)).recordFailedAttempt(username, ipAddress);
        }

        mockMvc.perform(post("/api/v1.0/auth/login")
                        .param("username", username)
                        .param("password", password))
                .andExpect(status().isOk())
                .andExpect(content().string("Login successful."));

        //verifying that attempts are reset after a successful login
        verify(rateLimiterService, times(1)).resetAttempts(username, ipAddress);
    }

    //test case: custom error handling messages
    @Test
    public void testCustomErrorMessages() throws Exception {
        //simulating invalid login attempt
        when(authenticationManager.authenticate(any()))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        mockMvc.perform(post("/api/v1.0/auth/login")
                        .param("username", username)
                        .param("password", invalidPassword))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Invalid credentials"));

        //simulating the rate-limit exceeded error message
        when(rateLimiterService.isBlocked(username, ipAddress)).thenReturn(true);

        mockMvc.perform(post("/api/v1.0/auth/login")
                        .param("username", username)
                        .param("password", invalidPassword))
                .andExpect(status().isTooManyRequests())
                .andExpect(content().string("Login attempts exceeded. Please try again later."));
    }
}