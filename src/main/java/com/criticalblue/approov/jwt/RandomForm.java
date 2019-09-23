package com.criticalblue.approov.jwt;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class RandomForm {

    private final Random random = new Random();

    private static List<String> list = new ArrayList<String>();

    static {
        list.add("Sphere");
        list.add("Cone");
        list.add("Cube");
        list.add("Box");
    }

    public String create() {

        int index = random.nextInt(list.size());
        return list.get(index);
    }
}
