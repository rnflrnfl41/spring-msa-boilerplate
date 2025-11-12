package com.example.authserver.service;

import com.example.authserver.dto.SignupRequest;
import com.example.authserver.dto.SocialSignupRequest;
import com.example.authserver.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class SignupService {

    private final UserRepository userRepository;

    public void signupLocal(SignupRequest request) {
        log.info("로컬 회원가입 처리 loginId={}, email={}", request.loginId(), request.email());
        // TODO: 로컬 회원가입 저장 로직 구현
    }

    public void signupSocial(SocialSignupRequest request) {
        log.info("소셜 회원가입 처리 provider={}, providerId={}, email={}",
                request.provider(), request.providerId(), request.email());
        // TODO: 소셜 회원가입 저장 로직 구현
    }
}
