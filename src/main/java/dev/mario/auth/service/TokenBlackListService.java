package dev.mario.auth.service;

import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class TokenBlackListService {
    private final Set<String> blacklist = ConcurrentHashMap.newKeySet();

    public void addToken(String token) {
        blacklist.add(token);
    }

    public boolean containToken(String token) {
        return blacklist.contains(token);
    }
}
