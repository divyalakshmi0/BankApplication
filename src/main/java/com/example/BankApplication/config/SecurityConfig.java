package com.example.BankApplication.config;

import com.example.BankApplication.service.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private AccountService accountService;

    @Bean
    public static PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable()) // Consider enabling CSRF protection in production
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/register").permitAll() // Allow registration without authentication
                .anyRequest().authenticated()) // All other requests require authentication
            .formLogin(form -> form
                .loginPage("/login") // Custom login page
                .defaultSuccessUrl("/dashboard", true) // Redirect to dashboard on successful login
                .permitAll()) // Allow everyone to access the login page
            .logout(logout -> logout
                .invalidateHttpSession(true) // Invalidate session on logout
                .clearAuthentication(true) // Clear authentication
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout")) // Logout URL
                .logoutSuccessUrl("/login?logout") // Redirect to login page after logout
                .permitAll()) // Allow everyone to access logout
            .headers(header -> header
                .frameOptions(frameOptions -> frameOptions.sameOrigin())); // Allow iframe from the same origin
        return http.build();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(accountService).passwordEncoder(passwordEncoder());
    }
}
