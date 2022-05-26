package com.michael;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.io.File;

import static com.michael.constant.FileConstant.USER_FOLDER;

@SpringBootApplication
public class PortalApplication {

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }



    public static void main(String[] args) {
        SpringApplication.run(PortalApplication.class, args);
        new File(USER_FOLDER).mkdirs();
    }

}
