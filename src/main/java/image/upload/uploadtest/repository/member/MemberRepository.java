package image.upload.uploadtest.repository.member;

import image.upload.uploadtest.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member,Long> {
    Optional<Member> findByUsername(String username);

    boolean existsByUsernameOrNickname(String username,String nickname);

    boolean existsByUsername(String username);

    boolean existsByNickname(String nickname);
}
