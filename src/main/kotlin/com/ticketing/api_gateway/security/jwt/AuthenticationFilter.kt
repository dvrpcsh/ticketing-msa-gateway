package com.ticketing.api_gateway.security.jwt

import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

/**
 * API 게이트웨이의 모든 요청에 대해 JWT 토큰을 검증하는 커스텀 필어
 */
@Component
class AuthenticationFilter (
    private val jwtTokenProvider: JwtTokenProvider,
    private val redisTemplate: RedisTemplate<String, String>
): AbstractGatewayFilterFactory<AuthenticationFilter.Config>(Config::class.java) {

    //이 필터가 동작할 때 필요한 설정이 있으면 여기에 정의
    class Config

    /**
     * 실제 필터링 로직을 수행하는 부분
     *
     * 1.요청 헤더에 'Authorization' 헤더가 있는지 확인합니다.(없으면 401)
     * 2.'Bearer' 토큰이 맞는지 확인하고 순수한 토큰 문자열울 추출합니다.
     * 3.토큰의 유효성 검사를 합니다. (유효성 검사 실패 시 401 반환)
     * 4.Redis의 Denylist를 확인하여 로그아웃된 토큰인지 검사합니다.
     * 5.모든 검증을 통과하면 토큰에서 사용자 정보(이메일, 역할 등)를 추출합니다.
     * 6.요청 객체를 수정하여 "X-User-Email", "X-User-Role"과 같은 내부용 헤더에 사용자 정보를 담습니다.
     * 7.수정된 요청을 다음 필터 또는 마이크로서비스로 전달합니다.
     */
    override fun apply(config: Config): GatewayFilter {
        return GatewayFilter { exchange, chain ->
            val request = exchange.request
            val headers = request.headers

            //1.Authorization 헤더 존재 여부 확인
            if(!headers.containsKey(HttpHeaders.AUTHORIZATION)) {
                return@GatewayFilter onError(exchange, "Athorization 헤더가 없습니다.", HttpStatus.UNAUTHORIZED)
            }

            //2.Bearer 토큰 형식 확인 및 추출
            val authorizationHeader = headers[HttpHeaders.AUTHORIZATION]!![0]
            if(!authorizationHeader.startsWith("Bearer ")) {
                return@GatewayFilter onError(exchange, "Bearer 토큰이 아닙니다.", HttpStatus.UNAUTHORIZED)
            }
            val token = authorizationHeader.substring(7)

            //3.토큰 유효성 검증
            if(!jwtTokenProvider.validateToken(token)) {
                return@GatewayFilter onError(exchange, "토큰이 유효하지 않습니다.", HttpStatus.UNAUTHORIZED)
            }

            //4.로그아웃 된 토큰인지 확인
            if(redisTemplate.opsForValue().get(token) != null) {
                return@GatewayFilter onError(exchange, "로그아웃 된 토큰입니다.", HttpStatus.UNAUTHORIZED)
            }

            //5.토큰에서 정보 추출
            val authentication = jwtTokenProvider.getAuthentication(token)
            val userEmail = authentication.name
            val userRole = authentication.authorities.first().authority

            //6.요청 헤더에 사용자 정보 추가
            val modifiedRequest = request.mutate()
                .header("X-User-Email", userEmail)
                .header("X-User-Role", userRole)
                .build()

            //7.수정된 요청으로 다른 필터 체인 실행
            chain.filter(exchange.mutate().request(modifiedRequest).build())
        }
    }

    //에러 발생 시 HTTP 응답을 생성하는 헬퍼 메서드
    private fun onError(exchange: ServerWebExchange, err: String, httpStatus: HttpStatus): Mono<Void> {
        val response = exchange.response
        response.statusCode = httpStatus
        //logger.error(err) //실제 운영 시 로그를 남기는 것을 권장
        return response.setComplete()
    }
}