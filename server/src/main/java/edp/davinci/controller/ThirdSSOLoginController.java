package edp.davinci.controller;

import com.alibaba.fastjson.JSONArray;
import edp.core.annotation.AuthIgnore;
import edp.core.exception.UnAuthorizedException;
import edp.core.utils.TokenUtils;
import edp.davinci.core.common.Constants;
import edp.davinci.core.common.ResultMap;
import edp.davinci.dao.OrganizationMapper;
import edp.davinci.dao.RelRoleUserMapper;
import edp.davinci.dao.RelUserOrganizationMapper;
import edp.davinci.dao.RoleMapper;
import edp.davinci.dao.UserMapper;
import edp.davinci.dto.organizationDto.OrganizationBaseInfo;
import edp.davinci.dto.organizationDto.OrganizationCreate;
import edp.davinci.dto.organizationDto.OrganizationInfo;
import edp.davinci.dto.roleDto.RoleBaseInfo;
import edp.davinci.dto.userDto.UserLoginResult;
import edp.davinci.model.RelRoleUser;
import edp.davinci.model.RelUserOrganization;
import edp.davinci.model.Role;
import edp.davinci.model.ThirdSSOLogin;
import edp.davinci.model.User;
import edp.davinci.service.OrganizationService;
import edp.davinci.service.UserService;
import java.io.UnsupportedEncodingException;
import java.util.Base64;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.joda.time.DateTime;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping(value = Constants.BASE_API_PATH + "/3rdsso/login", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class ThirdSSOLoginController {

    @Autowired
    private UserService userService;

    @Autowired
    private TokenUtils tokenUtils;

    @Autowired
    private Environment environment;

    Base64.Decoder decoder = Base64.getDecoder();

    @PostMapping
    @AuthIgnore
    public ResponseEntity login(@RequestBody ThirdSSOLogin loginInfo) {
        String tk = loginInfo.getTicket();

        try {
            User user = getUser(tk);
            if (!user.getActive()) {
                log.error("User is not active, username:{}", user.getUsername());
                ResultMap resultMap = new ResultMap(tokenUtils).failWithToken(tokenUtils.generateToken(user)).message("This user is not active");
                return ResponseEntity.status(resultMap.getCode()).body(resultMap);
            }
            UserLoginResult userLoginResult = new UserLoginResult(user);
            String statistic_open = environment.getProperty("statistic.enable");
            if ("true".equalsIgnoreCase(statistic_open)) {
                userLoginResult.setStatisticOpen(true);
            }

            return ResponseEntity.ok(new ResultMap().success(tokenUtils.generateToken(user)).payload(userLoginResult));
        } catch (Exception ex) {
            return ResponseEntity.badRequest().build();
        }
    }

    @Autowired
    private UserMapper userMapper;
    @Autowired
    OrganizationService organizationService;
    @Autowired
    public OrganizationMapper organizationMapper;
    @Autowired
    private RoleMapper roleMapper;
    @Autowired
    private RelRoleUserMapper relRoleUserMapper;
    @Autowired
    private RelUserOrganizationMapper relUserOrganizationMapper;

    private User getUser(String ticket) throws UnsupportedEncodingException {
        byte[] buf = decoder.decode(ticket);
        String str = new String(buf, "utf-8");

        JSONArray ja = JSONArray.parseArray(str);

        SSOUser sso = new SSOUser();

        sso.id = ja.getJSONArray(0).getString(0);
        sso.name = ja.getJSONArray(0).getString(1);
        sso.orgName = ja.getJSONArray(1).getString(0);
        sso.deptName = ja.getJSONArray(1).getString(1);
        sso.roles = ja.getJSONArray(2).toArray(new String[0]);

        User user = userService.getByUsername(sso.id);
        boolean orgExist = organizationService.isExist(sso.orgName, null, null);
        boolean createUser = false;
        if (user == null) {
            user = new User();
            user.setAdmin(!orgExist);

            user.setActive(Boolean.TRUE);
            user.setUsername(sso.id);
            user.setName(sso.name);
            user.setPassword("<null>");
            user.setEmail("<null>");
            user.setDepartment(sso.deptName);
            user.setCreateTime(DateTime.now().toDate());
            user.setCreateBy(0L);
            userMapper.insert(user);
            createUser = true;
        } else {
            if (user.getDepartment() != null && !user.getDepartment().equals(sso.deptName)) {
                user.setDepartment(sso.deptName);
                user.setUpdateTime(DateTime.now().toDate());
                user.setUpdateBy(0L);
                userMapper.updateBaseInfo(user);
            }
        }
        { //公司与角色管理
            Long orgId = -1L;
            if (!orgExist) {
                OrganizationCreate orgCrt = new OrganizationCreate();
                orgCrt.setName(sso.orgName);
                orgCrt.setDescription("create by 3rd SSO");
                OrganizationBaseInfo org = organizationService.createOrganization(orgCrt, user);
                orgId = org.getId();
            } else {
                orgId = organizationMapper.getIdByName(sso.orgName);
            }
            {//用户与组织关联关系
                try {//检查
                    organizationService.getOrganization(orgId, user);
                } catch (UnAuthorizedException ex) {//没关联，则报 UnAuthorizedException 异常
                    RelUserOrganization relUserOrganization = new RelUserOrganization();
                    relUserOrganization.setOrgId(orgId);
                    relUserOrganization.setUserId(user.getId());
                    relUserOrganization.setCreateBy(0L);
                    relUserOrganization.setCreateTime(DateTime.now().toDate());
                    relUserOrganizationMapper.insert(relUserOrganization);
                }
            }
            List<RoleBaseInfo> sysRoles = roleMapper.getBaseInfoByOrgId(orgId);
            List<Role> userRoles = roleMapper.getRolesByOrgAndUser(orgId, user.getId());
            for (String roleName : sso.roles) {
                //角色存在
                if (sysRoles != null && sysRoles.stream().filter(sr -> sr.getName().equals(roleName)).count() > 0) {
                    RoleBaseInfo sysRole = sysRoles.stream().filter(sr -> sr.getName().equals(roleName)).findFirst().get();
                    //用户已经与角色关联
                    if (userRoles != null && userRoles.stream().filter(sr -> sr.getName().equals(roleName)).count() > 0) {
                        continue;
                    } else {
                        //创建用户与已有角色关联
                        RelRoleUser roleUser = new RelRoleUser();
                        roleUser.setRoleId(sysRole.getId());
                        roleUser.setUserId(user.getId());
                        roleUser.setCreateBy(0L);
                        roleUser.setCreateTime(DateTime.now().toDate());
                        relRoleUserMapper.insert(roleUser);
                    }
                    continue;
                } else {
                    //创建角色
                    Role role = new Role();
                    role.setOrgId(orgId);
                    role.setName(roleName);
                    role.setCreateBy(0L);
                    role.setCreateTime(DateTime.now().toDate());
                    roleMapper.insert(role);
                    //创建用户和角色关联
                    RelRoleUser roleUser = new RelRoleUser();
                    roleUser.setRoleId(role.getId());
                    roleUser.setUserId(user.getId());
                    roleUser.setCreateBy(0L);
                    roleUser.setCreateTime(DateTime.now().toDate());
                    relRoleUserMapper.insert(roleUser);
                }
            }
        }
        //重新获取用户信息
        user = userService.getByUsername(sso.id);
        return user;
    }

    private class SSOUser {

        String id;
        String name;
        String orgName;
        String deptName;
        String[] roles;
    }
}
