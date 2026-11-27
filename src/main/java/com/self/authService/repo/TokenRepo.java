package com.self.authService.repo;

import com.self.authService.enums.TokenType;
import com.self.authService.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface TokenRepo extends JpaRepository<RefreshToken , String> {

    Optional<RefreshToken> findByTokenAndType(String token, TokenType type);
}
