package image.upload.uploadtest;

import image.upload.uploadtest.dto.member.join.JoinRequest;
import image.upload.uploadtest.entity.Member;
import image.upload.uploadtest.repository.member.MemberRepository;
import image.upload.uploadtest.service.member.MemberService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@RequiredArgsConstructor
public class UploadtestApplication {

	private final MemberService memberService;

	public static void main(String[] args) {
		SpringApplication.run(UploadtestApplication.class, args);
	}

	@PostConstruct
	public void init(){
		JoinRequest joinRequest = new JoinRequest("user", "1234", "1234", "user", "user@user.com");
		memberService.joinMember(joinRequest);

		JoinRequest joinRequest1 = new JoinRequest("user2","1234","1234","user2","user2@user2.com");
		memberService.joinMember(joinRequest1);
	}
}
