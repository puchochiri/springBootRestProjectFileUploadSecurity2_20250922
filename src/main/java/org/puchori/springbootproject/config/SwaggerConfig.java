package org.puchori.springbootproject.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.servers.Server;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "Boot 01 Project Swagger",
                version = "v1.0",
                description = "Spring Boot 3.x API 문서",
                contact = @Contact(name = "관리자", email = "admin@example.com")
        ),
        servers = {
                @Server(url = "http://localhost:9050", description = "Local Server")
        }
)
public class SwaggerConfig {
        //http://localhost:9050/swagger-ui/index.html
}