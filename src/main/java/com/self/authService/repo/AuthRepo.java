package com.self.authService.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.self.authService.model.Users;

import java.util.Optional;

@Repository 
public interface AuthRepo extends JpaRepository<Users , String>{

    Optional<Users> findByEmailIgnoreCase(String email);
}
