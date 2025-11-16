package com.example.authserver.controller;

import com.example.authserver.dto.SignupRequest;
import com.example.authserver.dto.SocialSignupRequest;
import com.example.authserver.service.SignupService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Optional;
import java.util.regex.Pattern;

@Controller
@RequiredArgsConstructor
public class SignupController {

    //TODO: validation 강화(이름 3글자 이상 등등)

    private final SignupService signupService;
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$");
    private static final Pattern PHONE_PATTERN = Pattern.compile("^[0-9\\-]{9,20}$");

    @GetMapping("/signup")
    public String signupPage(@RequestParam(name = "social", required = false) String socialParam,
                             @RequestParam(name = "provider", required = false) String provider,
                             @RequestParam(name = "providerId", required = false) String providerId,
                             @RequestParam(name = "email", required = false) String email,
                             Model model) {
        boolean isSocial = "true".equalsIgnoreCase(Optional.ofNullable(socialParam).orElse(""));
        model.addAttribute("isSocial", isSocial);

        if (isSocial) {
            SocialSignupRequest form = new SocialSignupRequest(
                    Optional.ofNullable(provider).orElse(""),
                    Optional.ofNullable(providerId).orElse(""),
                    Optional.ofNullable(email).orElse(""),
                    "",
                    ""
            );
            model.addAttribute("form", form);
        } else {
            model.addAttribute("form", new SignupRequest("", "", "", "", "",""));
        }
        return "signup";
    }

    @PostMapping("/signup")
    public String signup(@ModelAttribute("form") SignupRequest request,
                         BindingResult bindingResult,
                         Model model) {
        model.addAttribute("isSocial", false);

        validateLocalSignup(request, bindingResult);

        if (bindingResult.hasErrors()) {
            return "signup";
        }

        signupService.signupLocal(request);
        return "redirect:/login?signupSuccess";
    }

    @PostMapping("/signup/social")
    public String socialSignup(@ModelAttribute("form") SocialSignupRequest request,
                               BindingResult bindingResult,
                               Model model) {
        model.addAttribute("isSocial", true);

        validateSocialSignup(request, bindingResult);
        if (bindingResult.hasErrors()) {
            return "signup";
        }

        signupService.signupSocial(request);
        return "redirect:/login?signupSuccess";
    }

    private void validateLocalSignup(SignupRequest request, BindingResult bindingResult) {
        if (!StringUtils.hasText(request.name())) {
            bindingResult.rejectValue("name", "name.required", "이름을 입력해주세요.");
        }
        if (!StringUtils.hasText(request.loginId())) {
            bindingResult.rejectValue("loginId", "loginId.required", "로그인 아이디를 입력해주세요.");
        }
        if (!StringUtils.hasText(request.email())) {
            bindingResult.rejectValue("email", "email.required", "이메일을 입력해주세요.");
        } else if (!EMAIL_PATTERN.matcher(request.email()).matches()) {
            bindingResult.rejectValue("email", "email.invalid", "올바른 이메일 형식이 아닙니다.");
        }
        if (!StringUtils.hasText(request.password())) {
            bindingResult.rejectValue("password", "password.required", "비밀번호를 입력해주세요.");
        } else if (request.password().length() < 8 || request.password().length() > 64) {
            bindingResult.rejectValue("password", "password.length", "비밀번호는 8자 이상 64자 이하로 입력해주세요.");
        }
        if (!StringUtils.hasText(request.passwordConfirm())) {
            bindingResult.rejectValue("passwordConfirm", "passwordConfirm.required", "비밀번호 확인을 입력해주세요.");
        }
        if(!request.password().equals(request.passwordConfirm())){
            bindingResult.rejectValue("passwordConfirm", "passwordConfirm.invalid", "비밀번호가 일치하지 않습니다.");
        }
    }

    private void validateSocialSignup(SocialSignupRequest request, BindingResult bindingResult) {
        if (!StringUtils.hasText(request.provider())) {
            bindingResult.reject("provider.required", "소셜 제공자 정보가 없습니다. 다시 시도해주세요.");
        }

        if (!StringUtils.hasText(request.providerId())) {
            bindingResult.reject("providerId.required", "소셜 제공자 ID가 없습니다. 다시 시도해주세요.");
        }

        if (!StringUtils.hasText(request.name())) {
            bindingResult.rejectValue("name", "name.required", "이름을 입력해주세요.");
        }

        if (!StringUtils.hasText(request.phone())) {
            bindingResult.rejectValue("phone", "phone.required", "휴대폰 번호를 입력해주세요.");
        }else if (StringUtils.hasText(request.phone()) && !PHONE_PATTERN.matcher(request.phone()).matches()) {
            bindingResult.rejectValue("phone", "phone.invalid", "휴대폰 번호 형식이 올바르지 않습니다.");
        }
    }
}
