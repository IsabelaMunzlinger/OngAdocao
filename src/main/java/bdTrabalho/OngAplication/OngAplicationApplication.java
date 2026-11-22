package bdTrabalho.OngAplication;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class OngAplicationApplication {

	public static void main(String[] args) {
		SpringApplication.run(OngAplicationApplication.class, args);
	}
}
