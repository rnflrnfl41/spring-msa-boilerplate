package com.example.infra.annotation;

import com.example.infra.config.WebClientConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(WebClientConfig.class)
public @interface EnableWebClientConfig {
}
