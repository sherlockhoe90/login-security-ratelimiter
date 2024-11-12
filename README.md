# Getting Started : Login-Security-RateLimiter

## Reference Documentation

### Task: Implement Login Functionality with Rate Limiting in Spring Boot

**Objective**: Design a secure login system in Spring Boot using Spring Security, with a rate-limiting mechanism to
_prevent brute-force_ attacks, as well as _DDOS_ attacks.

1. Login Functionality:
    * a. Set up a basic login endpoint using Spring Security.
    * b. Use an in-memory user store for simplicity, with at least one user
      (username: user, password: password).
    * c. Use BCryptPasswordEncoder for hashing passwords.
2. Rate-Limiting for Login Attempts:
    * a. Implement a rate-limiting mechanism that restricts the number of login
      attempts from a specific IP address or username.
    * b. Allow up to 5 failed login attempts within a 15-minute window. After the
      limit is exceeded, block further attempts for that user or IP for a cooldown
      period of 30 minutes.
    * c. Ensure the rate limit resets after successful login.
3. Error Handling and Messages:
    * a. Provide appropriate error messages for:
        * i. Invalid credentials.
        * ii. Exceeded login attempts with the remaining time for when the user
          can try again.
4. Logging:
    * a. Log each login attempt (success and failure), including the username, IP
      address, and timestamp.
5. Testing:
    * a. Include test cases to verify:
        * i. Successful login.
        * ii. Rate limiting when the maximum number of failed attempts is
          reached.
          iii. Resetting of the attempt count after a successful login.

#### Bonus (Optional):
* Extend the rate-limiting feature to integrate with Redis for scalability if multiple
  instances are running.
* Provide configuration properties to control the threshold and cooldown period for
  failed attempts.

#### Deliverables:
* Source code for the Spring Boot application with appropriate configuration files.
* Documentation or comments within the code explaining each major part.
* Test cases verifying the expected functionality.