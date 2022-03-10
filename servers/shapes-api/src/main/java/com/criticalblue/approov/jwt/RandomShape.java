package com.criticalblue.approov.jwt;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class RandomShape {
    private final Random random = new Random();

    private static List<String> list = new ArrayList<String>();

    static {
        list.add("Circle");
        list.add("Triangle");
        list.add("Square");
        list.add("Rectangle");
    }

    public String create() {

        int index = random.nextInt(list.size());
        return list.get(index);
    }
}
