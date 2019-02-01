package com.higgsup.security.entity;

import javax.persistence.*;
import java.util.List;

@Entity
@Table(name="app_user")
public class AppUser {
    @Id @Column(name="id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(name="username")
    private String username;
    
    @Column(name="password")
    private String password;
    
    @OneToMany
    @JoinColumn(name="user_id", referencedColumnName="id")
    private List<UserRole> roles;
    
    public AppUser() { }
    
    public AppUser(Long id, String username, String password, List<UserRole> roles) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.roles = roles;
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public List<UserRole> getRoles() {
        return roles;
    }
}
