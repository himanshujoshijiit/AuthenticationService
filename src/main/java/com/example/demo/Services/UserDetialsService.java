package com.example.demo.Services;

import java.util.Optional;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.example.demo.Repository.UserRepository;

public class UserDetialsService {
    private final UserRepository userRepository;

    public UserDetialsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<com.example.demo.models.User> user = userRepository.findByUsername(username);

        if (user.isEmpty()) {
            throw new UsernameNotFoundException("User not found: " + username);
        }

        return User.withUsername(user.get().getUsername())
                .password(user.get().getpassword())
                .role(user.get().getRole())
                .build();
    }
}
