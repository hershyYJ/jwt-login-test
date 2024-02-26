package com.team.leaf.user.account.jwt;

import com.team.leaf.user.account.entity.AccountDetail;
import com.team.leaf.user.account.repository.AccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    public final AccountRepository accountRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        AccountDetail accountDetail = accountRepository.findByEmail(email).orElseThrow(
                () -> new RuntimeException("Not found User")
        );

        PrincipalDetails userDetails = new PrincipalDetails();
        userDetails.setAccountDetail(accountDetail);

        return userDetails;
    }
}
