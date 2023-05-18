package com.example.demo.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;

@Data
@Entity
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(uniqueConstraints = {@UniqueConstraint(columnNames = "username")})
public class UserEntity {
    @Id
    @GeneratedValue(generator = "system-uuid")
    @GenericGenerator(name = "system-uuid", strategy = "uuid")
    private String id;  // 유저에게 고유하게 부여되는 id

    @Column
    private String username;    // 아이디로 사용할 유저네임. 이메일일 수도 그냥 문자열일 수도 있다.
    private String password; // 패스워드
    private String role;    // 사용자 롤. 예: 어드민, 일반사용자
    private String authProvider;    // 이후 Oauth에서 사용할 유저 정보 제공자: github


}
