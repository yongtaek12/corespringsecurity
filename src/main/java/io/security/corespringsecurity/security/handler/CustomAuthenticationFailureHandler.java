package io.security.corespringsecurity.security.handler;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

        String errorMessage = "Invalid Username or Password";

        if(exception instanceof BadCredentialsException){
            errorMessage = "Invalid Username or Password";
        }else if(exception instanceof InsufficientAuthenticationException){
            errorMessage = "Invalid Secret Key";
        }
        setDefaultFailureUrl("/login?error=ture&exception=" + exception.getMessage());

        //response 응답.
        super.onAuthenticationFailure(request, response, exception);
    }
}
