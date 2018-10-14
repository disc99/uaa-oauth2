package com.example.uaaoauth2;

import org.springframework.security.core.userdetails.User;

import static java.util.Collections.emptyList;

public class OAuth2User extends User {
    String email;

    public OAuth2User(String name, String password, String email) {
        super(name, password, emptyList());
        this.email = email;
    }

    public String getEmail() {
        return email;
    }
}
