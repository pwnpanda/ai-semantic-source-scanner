package com.example;

import java.util.HashMap;
import java.util.Map;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminController {

    private final Map<String, String> resources = new HashMap<>();

    @DeleteMapping("/admin/resource/{id}")
    public String deleteResource(@PathVariable String id) {
        // VULNERABLE: no @PreAuthorize / RequireAuthorization on a
        // privileged DELETE on a resource id. Miss-finder should flag
        // BOLA (resource id without authz), BFLA (privileged route
        // without authz), and missing-authn (state-changing op).
        if (resources.containsKey(id)) {
            resources.remove(id);
            return "deleted";
        }
        return "not-found";
    }
}
