package com.higgsup.security.user;

import com.higgsup.security.entity.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

/**
 * <b>File Created</b>: Feb 01, 2019
 *
 * <b>Author</b>: hungnh
 */
public interface UserRepository extends JpaRepository<AppUser, Long> {
    @Query("select u from AppUser u left join fetch u.roles r where u.username=:username")
    public Optional<AppUser> findByUsername(@Param("username") String username);
}
