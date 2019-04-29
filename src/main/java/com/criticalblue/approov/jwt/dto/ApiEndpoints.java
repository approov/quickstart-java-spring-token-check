package com.criticalblue.approov.jwt.dto;

import java.util.ArrayList;
import java.util.List;

public class ApiEndpoints {

    private final List endpoints;

    public ApiEndpoints() {
        this.endpoints = getEndpoints();
    }

    public List getEndpoints() {
        List<String> list = new ArrayList<String>();
        list.add("/forms");
        list.add("/shapes");

        return list;
    }
}
