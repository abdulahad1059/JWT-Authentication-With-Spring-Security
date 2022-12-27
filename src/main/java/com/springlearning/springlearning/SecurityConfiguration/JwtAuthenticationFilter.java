package com.springlearning.springlearning.SecurityConfiguration;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * This class will interrupt each of the api call and then validate user and decide weather to process the request or not
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtTokenHelper jwtTokenHelper;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request)
            throws ServletException {
        String path = request.getRequestURI();
        return path.contains("login");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {


        //token is like: Bearer  x.y.z

        //1. get token
        String requestToken = request.getHeader("Authorization");
        String username = null;
        String token = null;
        if (requestToken != null && requestToken.startsWith("Bearer")) {
            token = requestToken.substring(7);
            try {
                username = this.jwtTokenHelper.getUsernameFromToken(token);
            } catch (IllegalArgumentException e) {
                System.out.print("Unable to get JWT token");
            } catch (ExpiredJwtException e) {
                System.out.print("Token is expired");
            } catch (MalformedJwtException e) {
                System.out.print("Invalid jwt token");
            }
        } else {
            System.out.print("jwt token does not begin with Bearer");
        }

        //once we got the token,now validate it
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
            if (this.jwtTokenHelper.validateToken(token, userDetails)) {
                //now everything is fine and we have to do authentication for this user
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            } else {
                System.out.print("Invalid jwt token");
            }
        } else {
            System.out.print(":username is null or context is null");
        }

        //so if user is unauthorized after above process then  filterChain.doFilter(request, response) will proceed and JwtAuthenticationEntryPoint will get Called and return unauthorized user
        //otherwise request will be processed
        filterChain.doFilter(request, response);

        //if without authentication setup,if the flow comes at line no 84,then JwtAuthenticationEntryPoint will be called(as this is unauthorized exception) that in turn return 401
    }
}
