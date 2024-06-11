package com.lucastrigueiro.springbootauth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfigurations {

    @Autowired
    private SecurityFilter securityFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
            // Disable CSRF
            .csrf(CsrfConfigurer::disable)
            // Disable session management
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // Authorize requests
            .authorizeHttpRequests(auth -> auth
                // Allow access to the login route
                .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()

                // Allow access according to the user's role
                .requestMatchers(HttpMethod.POST, "/auth/adminRole").hasRole("ADMIN")
                .requestMatchers(HttpMethod.POST, "/auth/userRole").hasRole("USER")

                // Allow access according to the user's authority
                .requestMatchers(HttpMethod.POST, "/auth/authorityRead1").hasAuthority("AUTHORITY_READ1")
                .requestMatchers(HttpMethod.POST, "/auth/authorityRead2").hasAuthority("AUTHORITY_READ2")

                // Allows access according to multiple user roles
                .requestMatchers(HttpMethod.POST, "/auth/userOrAdminRole").hasAnyRole("ADMIN", "USER")
                // Allows access according to multiple user authorities
                .requestMatchers(HttpMethod.POST, "/auth/authorityRead1or2").hasAnyAuthority("AUTHORITY_READ1", "AUTHORITY_READ2")

                // Require authentication for all other routes
                .anyRequest().authenticated()
            )
            // Add the security filter before the UsernamePasswordAuthenticationFilter
            .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class)
            .build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


}
