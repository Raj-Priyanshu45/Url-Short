package com.self.authService.repo;

import com.self.authService.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TokenRepo extends JpaRepository<RefreshToken , String> {
}
