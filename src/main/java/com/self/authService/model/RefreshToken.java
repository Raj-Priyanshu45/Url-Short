package com.self.authService.model;

import com.self.authService.enums.TokenType;
import jakarta.persistence.*;
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
    @Enumerated(EnumType.STRING)
    private TokenType type;
    private String userId;

}
