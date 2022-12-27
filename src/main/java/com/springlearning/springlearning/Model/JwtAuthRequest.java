package com.springlearning.springlearning.Model;

import lombok.Data;

@Data
public class JwtAuthRequest {
    private String username;
    private String password;
}
