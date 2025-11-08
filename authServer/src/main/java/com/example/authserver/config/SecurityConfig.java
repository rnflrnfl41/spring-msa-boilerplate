package com.example.authserver.config;

import com.example.authserver.config.properties.AppProperties;
import com.example.authserver.handler.CustomLogoutSuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import com.example.authserver.handler.OAuth2LoginSuccessHandler;
import com.example.authserver.handler.FormLoginSuccessHandler;

@Configuration
@Order(2)
@RequiredArgsConstructor
@EnableConfigurationProperties(AppProperties.class)
public class SecurityConfig {

    private final OAuth2LoginSuccessHandler oauth2LoginSuccessHandler;
    private final FormLoginSuccessHandler formLoginSuccessHandler;
    private final CustomLogoutSuccessHandler logoutSuccessHandler;


    /**
     * BFF가 Authorization Code를 받을 수 있도록 설정
     */
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .requestCache(cache -> cache
                        .requestCache(new CustomRequestCache())
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login/**", "/css/**", "/js/**", "/images/**", "/error").permitAll()
                        .requestMatchers("/api/logout").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .successHandler(formLoginSuccessHandler)
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .successHandler(oauth2LoginSuccessHandler)
                ).logout(logout -> logout
                        .logoutUrl("/logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .logoutSuccessHandler(logoutSuccessHandler)
                );

        return http.build();
    }

}