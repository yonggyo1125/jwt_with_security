package org.koreait.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.koreait.commons.constants.MemberType;

@Entity
@Data @Builder
@NoArgsConstructor @AllArgsConstructor
public class Member extends BaseEntity {
    @Id
    @GeneratedValue
    private Long seq;
    @Column(length=60, unique = true, nullable = false)
    private String email;

    @Column(length=65, nullable = false)
    private String password;

    @Column(length=30, nullable = false)
    private String name;

    @Column(length=11)
    private String mobile;

    @Enumerated(EnumType.STRING)
    @Column(length=30, nullable = false)
    private MemberType type = MemberType.USER;
}
