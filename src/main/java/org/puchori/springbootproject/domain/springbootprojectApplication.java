package org.puchori.springbootproject.domain;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
public class springbootprojectApplication {

  public static void main(String[] args){
    SpringApplication.run(springbootprojectApplication.class,args);
  }

}
