package com.self.authService.repo;

import com.self.authService.enums.TokenType;
import com.self.authService.model.RefreshToken;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;

import java.util.Optional;

@Repository
public interface TokenRepo extends JpaRepository<RefreshToken , String> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
    SELECT t FROM RefreshToken t
    WHERE t.token = :token
    AND t.type = :type
""")
    Optional<RefreshToken> findByTokenForUpdate(
            @Param("token") String token,
            @Param("type") TokenType type
    );

    void deleteAllByExpTimeBefore(Instant expTime);

    void deleteByTokenAndType(String hash, TokenType tokenType);
}
