package com.springlearning.springlearning.api;

import com.springlearning.springlearning.Model.JwtAuthRequest;
import com.springlearning.springlearning.Model.User;
import com.springlearning.springlearning.SecurityConfiguration.JwtAuthReponse;
import com.springlearning.springlearning.SecurityConfiguration.JwtTokenHelper;
import org.hibernate.annotations.SelectBeforeUpdate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    @Autowired
    private JwtTokenHelper jwtTokenHelper;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/login")
    public ResponseEntity<JwtAuthReponse> createToken(@RequestBody JwtAuthRequest request) throws Exception {
        System.out.println(request.getUsername());
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(request.getUsername());
        this.authenticate(request.getUsername(), request.getPassword());
        String token = this.jwtTokenHelper.generateToken(userDetails);
        JwtAuthReponse response = new JwtAuthReponse();
        response.setToken(token);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    private void authenticate(String username, String password) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        try {
            this.authenticationManager.authenticate(usernamePasswordAuthenticationToken);
        } catch (BadCredentialsException e) {
            System.out.print("Invalid username or password");
            throw new BadCredentialsException("Invalid username or password");
        }
    }

}
