package com.springsecurity.security.repo;

import com.springsecurity.security.entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UsersRepo extends JpaRepository<Users,Integer> {

    public Optional<Users> findByUsername(String username);

}
