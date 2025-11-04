package com.example.authserver.config;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;

@Configuration
@RequiredArgsConstructor
public class AuthRedisCustomizer {

    private final RedisTemplate<String, Object> redisTemplate;
    private final ObjectMapper objectMapper;

    @PostConstruct
    public void customizeRedis() {
        // 🔹 전역 ObjectMapper를 복사해서 auth 모듈 전용으로 확장
        ObjectMapper customMapper = objectMapper.copy();
        ClassLoader loader = getClass().getClassLoader();

        // ✅ 1️⃣ Spring Security + OAuth2 직렬화 지원 모듈 등록
        customMapper.registerModules(SecurityJackson2Modules.getModules(loader));
        customMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());

        // ✅ 2️⃣ Java 8 Date/Time 지원
        customMapper.registerModule(new JavaTimeModule());
        customMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        customMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

        // ✅ 3️⃣ 타입 정보 유지 (Security 타입 역직렬화 필수)
        customMapper.activateDefaultTyping(
                LaissezFaireSubTypeValidator.instance,
                ObjectMapper.DefaultTyping.NON_FINAL,
                JsonTypeInfo.As.PROPERTY
        );

        // ✅ Redis Value Serializer 교체
        redisTemplate.setValueSerializer(new GenericJackson2JsonRedisSerializer(customMapper));
        redisTemplate.setHashValueSerializer(new GenericJackson2JsonRedisSerializer(customMapper));
        redisTemplate.afterPropertiesSet();

        System.out.println("✅ AuthServer RedisTemplate 직렬화 커스터마이징 완료");
    }
}