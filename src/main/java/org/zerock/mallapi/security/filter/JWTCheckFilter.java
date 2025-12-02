package org.zerock.mallapi.security.filter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.Map;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.zerock.mallapi.dto.MemberDTO;
import org.zerock.mallapi.util.JWTUtil;

import com.google.gson.Gson;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;

@Log4j2
public class JWTCheckFilter extends OncePerRequestFilter {
    
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request)
            throws ServletException {
        // Preflight 요청은 체크하지 않음
        if (request.getMethod().equals("OPTIONS")) {
            return true;
        }
        String path = request.getRequestURI();
        log.info("check url.........." + path);
        // /api/member/ 경로는 체크하지 않음 (로그인/토큰 갱신 등)
        if (path.startsWith("/api/members/")) {
            return true;
        }
        // 이미지 조회 경로는 체크하지 않음
        if (path.startsWith("/api/products/view/")) {
            return true;
        }
        return false;
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {
        
        log.info("--------------JWTCheckFilter-------------");
        String authHeaderStr = request.getHeader("Authorization");
        
        try {
            // Bearer 토큰 추출
            String accessToken = authHeaderStr.substring(7);
            // JWT 검증
            Map<String, Object> claims = JWTUtil.validateToken(accessToken);
            log.info("JWT Claims: " + claims);

            // 1. Claims에서 사용자 정보 추출
            String email = (String) claims.get("email");
            String pw = (String) claims.get("pw");
            String nickname = (String) claims.get("nickname");
            Boolean social = (Boolean) claims.get("social");
            // JWT는 JSON이므로 List<String> 캐스팅 시 예외 발생 가능성이 있음.
            // 필요시 Gson/Jackson 등을 이용해 안전하게 변환하는 로직 추가를 고려해야 합니다.
            @SuppressWarnings("unchecked")
            List<String> roleNames = (List<String>) claims.get("roleNames");

            // 2. MemberDTO 생성 (UserDetails 역할을 함)
            MemberDTO memberDTO = new MemberDTO(email, pw, nickname, social.booleanValue(), roleNames);
            log.info("---------------------------");
            log.info(memberDTO);
            log.info(memberDTO.getAuthorities());

            // 3. Authentication 객체 생성 및 SecurityContext에 저장 (권한 체크를 위해 필수)
            UsernamePasswordAuthenticationToken authenticationToken = 
                new UsernamePasswordAuthenticationToken(memberDTO, pw, memberDTO.getAuthorities());
            
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            // 4. 인증 설정을 완료한 후, 필터 체인 계속 진행 (딱 한 번)
            filterChain.doFilter(request, response);

        } catch (Exception e) {
            log.error("JWT Check Filter Error...........");
            log.error(e.getMessage());
            
            // JWT 검증 실패 시 JSON 응답 반환
            Gson gson = new Gson();
            String msg = gson.toJson(Map.of("error", "ERROR_ACCESS_TOKEN"));
            response.setContentType("application/json");
            
            PrintWriter printWriter = response.getWriter();
            printWriter.println(msg);
            printWriter.close();
            
            // Note: 예외 발생 시에는 filterChain.doFilter 호출을 하지 않아야 합니다.
        }
    } 
}