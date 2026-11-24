package com.self.authService.model;

import com.self.authService.enums.TokenType;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.*;
import org.hibernate.annotations.UuidGenerator;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Builder
public class RefreshToken {

    @Id
    @UuidGenerator
    @GeneratedValue
    private String id;
    private String token;
    private LocalDateTime expTime;
    private TokenType type;
    private String userId;

}
