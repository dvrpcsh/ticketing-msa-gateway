package com.ticketing.api_gateway.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain

/**
 * API 게이트웨이의 Spring Security 설정을 정의합니다.
 * 게이트웨이는 자체적으로 로그인/로그아웃을 처리하지 않으므로, 모든 보안 기능을 비활성화하고
 * 모든 요청을 허용하도록 설정합니다. 실제 인증은 커스텀필터에서 처리됩니다.
 */
@Configuration
@EnableWebFluxSecurity
class SecurityConfig {

    @Bean
    fun securityWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http
            .csrf{ it.disable() }
            .httpBasic{ it.disable() }
            .formLogin{ it.disable() }
            .authorizeExchange{
                it.anyExchange().permitAll()
            }
            .build()
    }
}