package com.self.authService.model;

import com.self.authService.enums.Provider;
import com.self.authService.enums.Roles;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.UuidGenerator;

@Entity 
@Getter
@Setter
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Users {

    @Id
    @UuidGenerator
    @GeneratedValue
    @Column(updatable = false , nullable = false)
    private String userId;
    private String username;
    @Enumerated(EnumType.STRING)
    private Roles roles;
    private String email;
    @Enumerated(EnumType.STRING)
    private Provider provider;
    private boolean emailVerified;
    private String password;
}
