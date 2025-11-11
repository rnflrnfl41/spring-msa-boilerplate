package com.example.authserver.repository;

import com.example.authserver.entity.UserInfo;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<UserInfo, UUID> {

    Optional<UserInfo> findByLoginId(String loginId);

}
