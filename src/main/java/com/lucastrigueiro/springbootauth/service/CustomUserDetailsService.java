package com.lucastrigueiro.springbootauth.service;

import com.lucastrigueiro.springbootauth.domain.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (username.equals("admin")) {
            return new User(1L, "admin", new BCryptPasswordEncoder().encode("123"));
        } else if (username.equals("lucas")) {
            return new User(2L, "lucas", new BCryptPasswordEncoder().encode("123"));
        }
        throw new UsernameNotFoundException("User not found");
    }
}
