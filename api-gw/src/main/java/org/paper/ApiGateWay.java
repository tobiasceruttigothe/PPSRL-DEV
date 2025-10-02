package org.paper;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class ApiGateWay {

    public static void main(String[] args) {
        SpringApplication.run(ApiGateWay.class, args);
    }

}
