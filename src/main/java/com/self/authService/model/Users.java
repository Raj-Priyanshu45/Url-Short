package com.self.authService.model;

import com.self.authService.enums.Roles;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.UuidGenerator;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(
        name = "User_table",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_users_username",
                        columnNames = "username"
                )
        }
)
public class Users {

    @Id
    @UuidGenerator
    @GeneratedValue
    @Column(updatable = false, nullable = false)
    private String userId;

    @Column(nullable = false, length = 30)
    private String username;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Roles roles;

    @Column(nullable = false, length = 254)
    private String email;

    @Column(nullable = false)
    private boolean emailVerified;

    private String passwordHash;
}
