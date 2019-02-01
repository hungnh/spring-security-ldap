package com.higgsup.security.entity;

public enum Role {
    MEMBER,
    ADMIN;
    
    public String authority() {
        return "ROLE_" + this.name();
    }
}
