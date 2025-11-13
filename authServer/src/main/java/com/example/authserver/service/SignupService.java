package com.example.authserver.service;

import com.example.authserver.dto.SignupRequest;
import com.example.authserver.dto.SocialSignupRequest;
import com.example.authserver.entity.Role;
import com.example.authserver.entity.UserInfo;
import com.example.authserver.entity.UserStatus;
import com.example.authserver.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.modelmapper.ModelMapper;

@Slf4j
@Service
@RequiredArgsConstructor
public class SignupService {

    private final UserRepository userRepository;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;

    public void signupLocal(SignupRequest request) {
        log.info("로컬 회원가입 처리 loginId={}, email={}", request.loginId(), request.email());
        UserInfo user = modelMapper.map(request, UserInfo.class);
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setRole(Role.ROLE_USER);
        user.setStatus(UserStatus.ACTIVE);
        userRepository.save(user);
    }

    public void signupSocial(SocialSignupRequest request) {
        log.info("소셜 회원가입 처리 provider={}, providerId={}, email={}",
                request.provider(), request.providerId(), request.email());
        UserInfo user = modelMapper.map(request, UserInfo.class);
        user.setRole(Role.ROLE_USER);
        user.setStatus(UserStatus.ACTIVE);
        userRepository.save(user);
    }
}
