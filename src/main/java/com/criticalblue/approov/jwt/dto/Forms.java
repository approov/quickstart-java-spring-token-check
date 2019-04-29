package com.criticalblue.approov.jwt.dto;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class Forms {

    private final String form;

    private final Random random = new Random();

    public Forms() {
        this.form = getForm();
    }

    public String getForm() {
        List<String> list = new ArrayList<String>();
        list.add("Sphere");
        list.add("Cone");
        list.add("Cube");
        list.add("Box");

        int index = random.nextInt(list.size());
        return list.get(index);
    }
}
