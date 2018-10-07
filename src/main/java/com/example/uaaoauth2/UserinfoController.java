package com.example.uaaoauth2;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserinfoController {

    @GetMapping("userinfo")
    Object userinfo(Authentication authentication) {
        Map<String, Object> userinfo = new LinkedHashMap<>();
//        userinfo.put("name", authentication.getName());
        Map<String, String> name = new HashMap<>();
        name.put("givenName", "gn");
        name.put("familyName", "fn");
        userinfo.put("name", name);
        userinfo.put("authorities", authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toList()));
        userinfo.put("firstName", "John");
        userinfo.put("lastName", "Doe");
        userinfo.put("email", "jdoe@example.com");
        userinfo.put("id", "xxxxxx");

        return userinfo;
    }
}