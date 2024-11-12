package com.assignment.loginsecurityratelimiter.service;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class LoginAttemptService {
    private static final Logger logger = LoggerFactory.getLogger(LoginAttemptService.class);

    private final StringRedisTemplate redisTemplate;
    private static final String FAILED_ATTEMPT_PREFIX = "failed_attempts:";  //redis key prefix for failed attempts
    private static final String BLOCKED_USER_PREFIX = "blocked_user:";  //redis key prefix for blocked users

    //threshold number of maximum failed attempts before blocking (default 5)
    @Value("${spring.redis.login-rate-limit.max-attempts:5}")
    private int maxAttempts;

    //time window for calculating failed attempts (default 15)
    @Value("${spring.redis.login-rate-limit.window:15}")
    private int attemptWindow;

    //cooldown period on getting blocked (30 minutes) (default 30)
    @Value("${spring.redis.login-rate-limit.cooldown:30}")
    private int cooldownPeriod;

    //checking if a user+IP is blocked due to too many failed attempts
    public boolean isBlocked(String username, String ipAddress) {
        String blockedKey = BLOCKED_USER_PREFIX + username + ":" + ipAddress;
        String blockedTime = redisTemplate.opsForValue().get(blockedKey);

        if (blockedTime != null) {
            LocalDateTime blockTime = LocalDateTime.parse(blockedTime);

            //checking if the cooldown period is over
            if (LocalDateTime.now().isAfter(blockTime.plusMinutes(cooldownPeriod))) {
                resetAttempts(username, ipAddress);  //resetting the count after cooldown period
                logger.info("Attempt reset for: User {} from IP {}", username, ipAddress);
                return false;  //user is now unblocked
            }
            logger.info("User {} from IP {} is blocked until {}", username, ipAddress, blockTime.plusMinutes(cooldownPeriod));
            return true;  //user is blocked
        }

        return false;  // Not blocked
    }

    //recording a failed login attempt in Redis for the username and IP address combination
    public void recordFailedAttempt(String username, String ipAddress) {
        String failedAttemptsKey = FAILED_ATTEMPT_PREFIX + username + ":" + ipAddress;
        String failedAttemptCount = redisTemplate.opsForValue().get(failedAttemptsKey);

        //increment failed attempts count or initialize if not found
        if (failedAttemptCount == null) {
            redisTemplate.opsForValue().set(failedAttemptsKey, "1", attemptWindow, TimeUnit.MINUTES);
            logger.warn("Login failed for user {} from IP {}. First failed attempt.", username, ipAddress);
        } else {
            int attempts = Integer.parseInt(failedAttemptCount);
            if (attempts < maxAttempts) {
                redisTemplate.opsForValue().increment(failedAttemptsKey, 1);
                logger.warn("Login failed for user {} from IP {}. Failed attempts : {}.", username, ipAddress, redisTemplate.opsForValue().get(failedAttemptsKey));
            } else {
                // Set block time in Redis when maximum attempts are exceeded
                String blockedUserKey = BLOCKED_USER_PREFIX + username + ":" + ipAddress;
                redisTemplate.opsForValue().set(blockedUserKey, LocalDateTime.now().toString(), cooldownPeriod, TimeUnit.MINUTES);
                logger.error("User {} from IP {} is blocked for {} minute(s) due to too many failed attempts", username, ipAddress, cooldownPeriod);
            }
        }
    }

    //resetting the failed attempts count and block status after a successful login
    public void resetAttempts(String username, String ipAddress) {
        String failedAttemptsKey = FAILED_ATTEMPT_PREFIX + username + ":" + ipAddress;
        redisTemplate.delete(failedAttemptsKey);

        String blockedUserKey = BLOCKED_USER_PREFIX + username + ":" + ipAddress;
        redisTemplate.delete(blockedUserKey);
        logger.info("Reset attempts count for User {} from IP {}.", username, ipAddress);
    }

}
