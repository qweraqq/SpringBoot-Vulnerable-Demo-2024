package com.shen1991.vulnerable;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

@SpringBootApplication
public class SpringBootVulnerableDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringBootVulnerableDemoApplication.class, args);
	}

}
