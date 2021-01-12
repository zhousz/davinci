package edp.davinci.controller;

import edp.core.annotation.AuthIgnore;
import edp.core.utils.TokenUtils;
import edp.davinci.core.common.Constants;
import edp.davinci.core.common.ResultMap;
import edp.davinci.dto.userDto.UserLoginResult;
import edp.davinci.model.ThirdSSOLogin;
import edp.davinci.model.User;
import edp.davinci.service.UserService;
import lombok.extern.slf4j.Slf4j;
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

    @PostMapping
    @AuthIgnore
    public ResponseEntity login(@RequestBody ThirdSSOLogin loginInfo){
        User user = userService.getByUsername("guest");
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

    }
}
