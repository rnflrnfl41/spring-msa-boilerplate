package com.example.authserver.repository;

import com.example.authserver.entity.UserSocialAccount;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserSocialAccountRepository extends JpaRepository <UserSocialAccount, UUID> {

    Optional<UserSocialAccount> findByEmailAndProviderAndProviderId(String email,String provider, String providerId);

}
