package com.michael.exceptions.domain;

public class UsernameExistException  extends Exception{

    public UsernameExistException(String message) {
        super(message);
    }
}
