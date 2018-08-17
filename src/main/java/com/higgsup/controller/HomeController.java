package com.higgsup.controller;

import com.higgsup.security.annotation.AllowAdmin;
import com.higgsup.security.annotation.AllowHigger;
import com.higgsup.security.context.SecurityContextFacade;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api")
public class HomeController {
    @AllowHigger
    @GetMapping("/higger")
    public String higger(Principal principal) {
        return String.format("Welcome Higger %s to the home page!", principal.getName());
    }

    @AllowAdmin
    @GetMapping("/admin")
    public String admin(Principal principal) {
        return String.format("Welcome Admin %s to the home page!", principal.getName());
    }
}
