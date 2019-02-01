package com.higgsup.security.user;

import com.higgsup.security.entity.AppUser;

import java.util.Optional;

public interface IUserService {
    Optional<AppUser> getByUsername(String username);
}
