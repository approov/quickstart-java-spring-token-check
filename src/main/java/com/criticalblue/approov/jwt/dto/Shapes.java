package com.criticalblue.approov.jwt.dto;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class Shapes {

    private final String shape;

    private final Random random = new Random();

    public Shapes() {
        this.shape = getShape();
    }

    public String getShape() {
        List<String> list = new ArrayList<String>();
        list.add("Circle");
        list.add("Triangle");
        list.add("Square");
        list.add("Rectangle");

        int index = random.nextInt(list.size());
        return list.get(index);
    }
}
