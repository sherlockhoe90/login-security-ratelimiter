package com.assignment.loginsecurityratelimiter.config;

import com.assignment.loginsecurityratelimiter.handlers.LoginFailureHandler;
import com.assignment.loginsecurityratelimiter.handlers.LoginSuccessHandler;
import com.assignment.loginsecurityratelimiter.service.LoginAttemptService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

//    private final LoginAttemptService loginAttemptService;
//    private final LoginFailureHandler loginFailureHandler;
//    private final LoginSuccessHandler loginSuccessHandler;
//
//    public SecurityConfig(LoginAttemptService loginAttemptService,
//                          LoginFailureHandler loginFailureHandler,
//                          LoginSuccessHandler loginSuccessHandler) {
//        this.loginAttemptService = loginAttemptService;
//        this.loginFailureHandler = loginFailureHandler;
//        this.loginSuccessHandler = loginSuccessHandler;
//    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/api/v1.0/auth/login").permitAll() // white listing the login endpoint to get permitted without authentication
                .anyRequest().authenticated()
                .and()
                .formLogin().disable() // disabling the default login form
                .csrf().disable(); // disabling CSRF as it is exclusively an api-based application
        }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean(); // making sure the AuthenticationManager bean is created
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // in-memory authentication and user setup
        auth.inMemoryAuthentication()
                .passwordEncoder(passwordEncoder())
                .withUser("user")
                .password(passwordEncoder().encode("password"))
                .roles("USER")
                .and()
                .withUser("admin")
                .password(passwordEncoder().encode("adminpassword"))
                .roles("ADMIN");
    }
}

