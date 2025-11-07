package com.example.authserver.config;

import com.example.authserver.service.CustomOAuth2UserService;
import com.example.authserver.service.CustomOidcUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@RequiredArgsConstructor
public class LoginConfig {

    private final PasswordEncoder passwordEncoder;

    /**
     * 1️⃣ In-memory 사용자 등록 (테스트용)
     * 실제 운영에서는 DB 기반 UserDetailsService 구현체로 교체
     */
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
                .username("testuser")
                .password(passwordEncoder.encode("password"))
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
}
