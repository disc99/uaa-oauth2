package com.example.uaaoauth2;

import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static java.util.stream.Collectors.toList;

@RestController
public class ApiController {

    @GetMapping("userinfo")
    Object userinfo(@AuthenticationPrincipal OAuth2User user) {
        return new UserinfoResponse(
                user.getUsername(),
                new Name("gn","fn"),
                "John",
                "Doe",
                user.getEmail(),
                user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(toList())
        );
    }

    public static class UserinfoResponse {
        public String id;
        public Name name;
        public String firstName;
        public String lastName;
        public String email;
        public List<String> authorities;
        public UserinfoResponse(String id, Name name, String firstName, String lastName, String email, List<String> authorities) {
            this.id = id;
            this.name = name;
            this.firstName = firstName;
            this.lastName = lastName;
            this.email = email;
            this.authorities = authorities;
        }
    }

    public static class Name {
        public String givenName;
        public String familyName;
        public Name(String givenName, String familyName) {
            this.givenName = givenName;
            this.familyName = familyName;
        }
    }
}