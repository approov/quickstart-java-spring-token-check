package com.criticalblue.approov.jwt.dto;

public class Hello {
    private final String hello;

    public Hello() {
        this.hello = getHello();
    }

    public String getHello() {
        return "Hello World!";
    }
}
