package com.springsecurity.security.repo;

import com.springsecurity.security.entity.Authorities;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthoritiesRepo extends JpaRepository<Authorities, Integer> {
}
