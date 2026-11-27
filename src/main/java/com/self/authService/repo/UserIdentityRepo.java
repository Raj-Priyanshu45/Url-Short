package com.self.authService.repo;

import com.self.authService.enums.Provider;
import com.self.authService.model.UserIdentity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserIdentityRepo
        extends JpaRepository<UserIdentity, String> {

    Optional<UserIdentity> findByProviderAndProviderSubject(
            Provider provider,
            String providerSubject
    );
}