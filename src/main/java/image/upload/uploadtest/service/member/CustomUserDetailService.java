package image.upload.uploadtest.service.member;

import image.upload.uploadtest.dto.member.login.CustomUserDetails;
import image.upload.uploadtest.entity.Member;
import image.upload.uploadtest.repository.member.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Optional<Member> memberData = memberRepository.findByUsername(username);

        if(memberData.isPresent()){
            return new CustomUserDetails(memberData.get());
        }else{
            throw new UsernameNotFoundException("User not found with username: " + username);
        }

    }
}
