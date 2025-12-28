package org.javaboy.vhr.controller.test;

import org.javaboy.vhr.model.Role;
import org.javaboy.vhr.service.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * ClassName: RoleController
 * Package: org.javaboy.vhr.controller.test
 * Description:
 *
 * @Author 李梦冉
 * @Create 2025/12/28 19:27
 * @Version 1.0
 */
@RestController
@RequestMapping("/api/v1")
public class RoleController {
@Autowired
private RoleService roleService;
    @GetMapping("/allRoles")
    public List<Role> getAllRoles(){
        return roleService.getAllRoles();
    }
}
