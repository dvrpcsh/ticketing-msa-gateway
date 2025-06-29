# 1. 베이스 이미지 선택
# 우리 애플리케이션을 실행할 기본 환경을 선택합니다.
# Java 17을 지원하는 가벼운 amazoncorretto 이미지를 사용합니다.
FROM amazoncorretto:17-alpine-jdk

# 2. JAR 파일 경로를 담을 변수 선언
# Gradle 빌드 시 생성되는 JAR 파일의 경로를 ARG(인자)로 지정합니다.
ARG JAR_FILE=build/libs/*.jar

# 3. JAR 파일 복사
# 위에서 지정한 경로의 JAR 파일을 컨테이너 내부의 'app.jar'라는 이름으로 복사합니다.
COPY ${JAR_FILE} app.jar

# 4. 컨테이너 실행 명령어
# 이 컨테이너가 시작될 때, 'java -jar /app.jar' 명령어를 실행하여
# 복사해 둔 Spring Boot 애플리케이션을 실행하도록 설정합니다.
ENTRYPOINT ["java","-jar","/app.jar"]
