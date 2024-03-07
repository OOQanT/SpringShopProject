package image.upload.uploadtest.service.member;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Slf4j
@Service
@Getter
public class LogoutService {
    private Set<String> blacklist = new HashSet<>();

    public void addToBlacklist(String token){
        blacklist.add(token);
    }

    public boolean isBlacklisted(String token){
        return blacklist.contains(token);
    }
}
