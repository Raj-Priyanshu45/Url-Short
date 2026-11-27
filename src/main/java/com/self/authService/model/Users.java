package com.self.authService.model;

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
@Table(
        name = "User_table" ,
        uniqueConstraints = {
                @UniqueConstraint(
                        columnNames = { "email" , "username" }
                )
        }
)
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
    private boolean emailVerified;
    private String passwordHash;
}
