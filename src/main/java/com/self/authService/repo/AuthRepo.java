package com.self.authService.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.self.authService.model.Users;

@Repository 
public interface AuthRepo extends JpaRepository<String , Users>{
    
}
