package com.self.authService.model;

import com.self.authService.enums.Provider;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.UuidGenerator;

@Entity
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(
        name = "user_identity",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_provider_subject",
                        columnNames = {"provider", "provider_subject"}
                )
        }
)
public class UserIdentity {

    @Id
    @GeneratedValue
    @UuidGenerator
    private String id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private Users user;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Provider provider;

    @Column(name = "provider_subject", nullable = false)
    private String providerSubject;
}