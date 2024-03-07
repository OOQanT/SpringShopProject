package image.upload.uploadtest.service.member;

import image.upload.uploadtest.dto.member.join.JoinRequest;
import image.upload.uploadtest.entity.Member;
import image.upload.uploadtest.repository.member.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.NoSuchElementException;

@Slf4j
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Transactional
    public boolean joinMember(JoinRequest request){

        boolean exists = memberRepository.existsByUsernameOrNickname(request.getUsername(), request.getNickname());
        if(exists){
            return false;
        }

        Member member = new Member(request.getUsername(), bCryptPasswordEncoder.encode(request.getPassword()), request.getNickname(), request.getEmail());
        member.setRole("ROLE_USER");
        memberRepository.save(member);
        return true;
    }

    @Transactional
    public Member findMember(String username){
        Member member = memberRepository.findByUsername(username)
                .orElseThrow(() -> new NoSuchElementException("존재하지 않는 유저"));

        return member;
    }
}
