package com.springsecurity.security;

import com.springsecurity.security.binding.UserPrincipal;
import com.springsecurity.security.entity.Users;
import com.springsecurity.security.repo.UsersRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private UsersRepo repo;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users users = repo.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("user not found"));
        return new UserPrincipal(users);
    }
}
