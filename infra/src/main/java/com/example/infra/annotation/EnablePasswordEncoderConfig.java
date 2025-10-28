package com.example.infra.annotation;

import com.example.infra.config.PasswordEncoderConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(PasswordEncoderConfig.class)
public @interface EnablePasswordEncoderConfig {
}
