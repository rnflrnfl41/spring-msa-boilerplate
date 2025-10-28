package com.example.infra.annotation;

import com.example.infra.config.ModelMapperConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(ModelMapperConfig.class)
public @interface EnableModelMapperConfig {
}
