package com.michael.exceptions.domain;

public class EmailExistException  extends Exception{

    public EmailExistException(String message) {
        super(message);
    }
}
