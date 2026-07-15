package com.vulncheck;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Path;

public class DependencyTreeConverter {

    private final ObjectMapper objectMapper;


    DependencyTreeConverter() {
        objectMapper = new ObjectMapper();
    }


    public DependencyNode convert(Path json) {
        try {
            return objectMapper.readValue(json.toFile(), DependencyNode.class);
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert JSON to DependencyNode", e);
        }
    }

}
