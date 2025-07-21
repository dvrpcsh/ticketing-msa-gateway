package com.ticketing.api_gateway.security.jwt

import org.slf4j.LoggerFactory
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.filter.GlobalFilter
import org.springframework.core.Ordered
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

/**
 * 모든 요청에 대해 최우선으로 실행되는 전역 필터(Global Filter).
 * JWT 토큰 검증 및 인증을 담당합니다.
 */
@Component
class GlobalAuthFilter(
    private val jwtTokenProvider: JwtTokenProvider,
    private val redisTemplate: RedisTemplate<String, String>
) : GlobalFilter, Ordered {

    private val logger = LoggerFactory.getLogger(this::class.java)

    override fun filter(exchange: ServerWebExchange, chain: GatewayFilterChain): Mono<Void> {
        val request = exchange.request
        logger.info(">>> [Global Auth Filter] Request path: {}", request.uri.path)

        // 공개된 경로는 필터링을 건너뜁니다.
        if (isPublicEndpoint(request.uri.path)) {
            logger.info(">>> [Global Auth Filter] Public endpoint. Passing through...")
            return chain.filter(exchange)
        }

        val headers = request.headers
        if (!headers.containsKey(HttpHeaders.AUTHORIZATION)) {
            return onError(exchange, "Authorization 헤더가 없습니다.", HttpStatus.UNAUTHORIZED)
        }

        val authorizationHeader = headers[HttpHeaders.AUTHORIZATION]!![0]
        if (!authorizationHeader.startsWith("Bearer ")) {
            return onError(exchange, "Bearer 토큰이 아닙니다.", HttpStatus.UNAUTHORIZED)
        }
        val token = authorizationHeader.substring(7)

        if (!jwtTokenProvider.validateToken(token)) {
            return onError(exchange, "토큰이 유효하지 않습니다.", HttpStatus.UNAUTHORIZED)
        }

        if (redisTemplate.opsForValue().get(token) != null) {
            return onError(exchange, "로그아웃된 토큰입니다.", HttpStatus.UNAUTHORIZED)
        }

        val authentication = jwtTokenProvider.getAuthentication(token)
        val userEmail = authentication.name
        val userRole = authentication.authorities.first().authority
        val userId = jwtTokenProvider.getUserId(token)

        logger.info(">>> [Global Auth Filter] 인증 성공! 헤더를 추가합니다: User ID='{}', Email='{}'", userId, userEmail)

        val modifiedRequest = request.mutate()
            .header("X-User-Id", userId.toString())
            .header("X-User-Email", userEmail)
            .header("X-User-Role", userRole)
            .build()

        return chain.filter(exchange.mutate().request(modifiedRequest).build())
    }

    // 이 필터가 가장 먼저 실행되도록 우선순위를 최상으로 설정합니다.
    override fun getOrder(): Int {
        return -1
    }

    private fun isPublicEndpoint(path: String): Boolean {
        return path.startsWith("/api/users/signup") ||
                path.startsWith("/api/users/login") ||
                path.startsWith("/api/users/reissue") ||
                path.startsWith("/swagger-ui") ||
                path.startsWith("/v3/api-docs")
    }

    private fun onError(exchange: ServerWebExchange, err: String, httpStatus: HttpStatus): Mono<Void> {
        val response = exchange.response
        response.statusCode = httpStatus
        logger.error(">>> [Global Auth Filter] 인증 에러: {}", err)
        return response.setComplete()
    }
}