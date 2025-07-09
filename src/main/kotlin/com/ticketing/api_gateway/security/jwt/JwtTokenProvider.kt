package com.ticketing.api_gateway.security.jwt

import io.jsonwebtoken.*
import io.jsonwebtoken.security.Keys
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.stereotype.Component
import java.util.*
import javax.crypto.SecretKey

/**
 * Access Token과 Refresh Token을 생성하고, 유효성을 검증하며, 토큰에서 정보를 추출하는 핵심 클래스
 */
@Component
class JwtTokenProvider (
    // application.properties에 설정한 비밀키를 주입받음
    @Value("\${jwt.secret}") private val secret: String
) {
    // 주입받은 비밀키를 HMAC-SHA 알고리즘에 사용할 수 있는 SecretKey 객체로 변환
    private val key: SecretKey by lazy {
        Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret))
    }

    /**
     * 주어진 JWT 토큰에서 인증(Authentication) 정보를 추출합니다.
     *
     */
    fun getAuthentication(token: String): Authentication {
        val claims = parseClaims(token)
        val role = claims["role"] as String? ?: throw RuntimeException("토큰에 역할정보가 없습니다.")
        val authorities = listOf(SimpleGrantedAuthority("ROLE_$role"))

        return UsernamePasswordAuthenticationToken(claims.subject, "", authorities)
    }

    /**
     * 주어진 JWT 토큰의 유효성을 검증합니다.
     *
     */
    fun validateToken(token: String): Boolean {
        return try {
            parseClaims(token)
            true
        } catch (e: Exception) {
            // 모든 종류의 JWT 관련 예외를 한 번에 처리합니다.
            false
        }
    }

    /**
     * 토큰의 남은 유효 시간을 계산하여 밀리초 단위로 반환합니다.
     */
    fun getRemainingTime(token: String): Long {
        return parseClaims(token).expiration.time - Date().time
    }

    /**
     * 토큰 파싱을 위한 공통 메서드
     */
    private fun parseClaims(token: String): Claims {
        return Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(token)
            .body
    }
}