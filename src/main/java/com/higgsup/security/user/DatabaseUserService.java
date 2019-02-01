package com.higgsup.security.user;

import com.higgsup.security.entity.AppUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * <b>File Created</b>: Feb 01, 2019
 *
 * <b>Author</b>: hungnh
 */
@Service
public class DatabaseUserService implements IUserService {
    private final UserRepository userRepository;

    @Autowired
    public DatabaseUserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public Optional<AppUser> getByUsername(String username) {
        return this.userRepository.findByUsername(username);
    }
}
