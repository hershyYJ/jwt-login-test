package com.team.leaf.user.account.service;

import com.team.leaf.user.account.config.JwtSecurityConfig;
import com.team.leaf.user.account.dto.request.JoinRequest;
import com.team.leaf.user.account.dto.request.LoginRequest;
import com.team.leaf.user.account.dto.request.UpdateAccountDto;
import com.team.leaf.user.account.dto.response.AccountDto;
import com.team.leaf.user.account.dto.response.LoginAccountDto;
import com.team.leaf.user.account.dto.response.TokenDto;
import com.team.leaf.user.account.entity.AccountDetail;
import com.team.leaf.user.account.entity.RefreshToken;
import com.team.leaf.user.account.jwt.JwtTokenUtil;
import com.team.leaf.user.account.repository.AccountRepository;
import com.team.leaf.user.account.repository.RefreshTokenRepository;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class AccountService {

    private final AccountRepository accountRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenUtil jwtTokenUtil;
    private final JwtSecurityConfig jwtSecurityConfig;

    // 이메일 중복 여부 확인
    public boolean checkEmailDuplicate(String email) {
        return accountRepository.existsByEmail(email);
    }

    // 닉네임 중복여부 확인
    public boolean checkNickNameDuplicate(String nickName) {
        return accountRepository.existsByNickname(nickName);
    }

    public boolean checkPhoneDuplicate(String phone) {
        return accountRepository.existsByPhone(phone);
    }

    @Transactional
    public String join(JoinRequest request) {

        // 이메일 형식 확인
        String emailRegex = "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$";
        Pattern emailPattern = Pattern.compile(emailRegex);

        Matcher emailMatcher = emailPattern.matcher(request.getEmail());
        if (!emailMatcher.matches()) {
            throw new RuntimeException("이메일 형식이 올바르지 않습니다.");
        }

        /*
         비밀번호 유효성 검사 :
         비밀번호는 최소 9~20자로 구성되어야 하며 숫자, 영어 대소문자, 특수 문자를 포함한 공백 없는 문자열이어야 함
         */
        String passwordRegex = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\\S+$).{9,20}$";
        Pattern pwPattern = Pattern.compile(passwordRegex);

        Matcher pwMatcher = pwPattern.matcher(request.getPassword());

        if (!pwMatcher.matches()) {
            throw new RuntimeException("비밀번호는 최소 9~20자로 구성되어야 하며, 숫자, 영어 대문자, 영어 소문자, 특수 문자를 모두 포함해야 합니다.");
        }

        if(!request.getPassword().equals(request.getPasswordCheck())) {
            throw new RuntimeException("비밀번호가 일치하지 않습니다.");
        }

        // 번호 중복 체크
        if (accountRepository.existsByPhone(request.getPhone())) {
            throw new RuntimeException("해당 번호로 가입된 계정이 이미 존재합니다.");
        }

        // 닉네임 중복 체크
        if (accountRepository.existsByNickname(request.getNickname())) {
            throw new RuntimeException("이미 존재하는 닉네임입니다.");
        }

        AccountDetail accountDetail = AccountDetail.joinAccount(request.getEmail(),jwtSecurityConfig.passwordEncoder().encode(request.getPassword()), request.getPhone(), request.getNickname());
        accountRepository.save(accountDetail);
        return "Success Join";
    }

    @Transactional
    public LoginAccountDto login(LoginRequest request, HttpServletResponse response) {

        // 이메일로 유저 정보 확인
        AccountDetail accountDetail = accountRepository.findByEmail(request.getEmail()).orElseThrow(() ->
                new RuntimeException("사용자를 찾을 수 없습니다."));

        // 비밀번호 일치 확인
        if(!jwtSecurityConfig.passwordEncoder().matches(request.getPassword(), accountDetail.getPassword())) {
            throw new RuntimeException("비밀번호가 일치하지 않습니다.");
        }

        else {
            TokenDto tokenDto = jwtTokenUtil.createAllToken(request.getEmail());

            Optional<RefreshToken> refreshToken = refreshTokenRepository.findByUserEmail(request.getEmail());

            if(refreshToken.isPresent()) {
                refreshTokenRepository.save(refreshToken.get().updateToken(tokenDto.getRefreshToken()));
            }
            else {
                RefreshToken newToken = new RefreshToken(tokenDto.getRefreshToken(), request.getEmail());
                refreshTokenRepository.save(newToken);
            }

            setHeader(response, tokenDto);

            String access_token = tokenDto.getAccessToken();
            String refresh_token = tokenDto.getRefreshToken();

            return new LoginAccountDto(accountDetail.getEmail(),access_token,refresh_token);
        }
    }

    @Transactional
    public String updateUser(String email, UpdateAccountDto accountDto) {
        AccountDetail accountDetail = accountRepository.findByEmail(email).orElseThrow(() ->
                new RuntimeException("사용자를 찾을 수 없습니다."));

        // 비밀번호 수정 시 인코딩하여 저장
        if (accountDto.getPassword() != null && !accountDto.getPassword().isEmpty()) {
            String encodedPassword = jwtSecurityConfig.passwordEncoder().encode(accountDto.getPassword());
            accountDetail.updateAccount(accountDto.getEmail(), encodedPassword, accountDto.getName(), accountDto.getNickname(), accountDto.getPhone(), accountDto.getBirthday(), accountDto.getBirthyear(), accountDto.getUniversityName(), accountDto.getShippingAddress(), accountDto.getSchoolAddress(), accountDto.getWorkAddress());
        } else {
            accountDetail.updateAccount(accountDto.getEmail(), null, accountDto.getName(), accountDto.getNickname(), accountDto.getPhone(), accountDto.getBirthday(), accountDto.getBirthyear(), accountDto.getUniversityName(), accountDto.getShippingAddress(), accountDto.getSchoolAddress(), accountDto.getWorkAddress());
        }

        return "Success updateUser";
    }


    //유저 정보 조회
    public AccountDto getUser(String email) {
        AccountDetail accountDetail = accountRepository.findByEmail(email).orElseThrow(() ->
                new RuntimeException("사용자를 찾을 수 없습니다."));
        return new AccountDto(accountDetail);
    }

    @Transactional
    public String logout(String email) {
        RefreshToken refreshToken = refreshTokenRepository.findByUserEmail(email).orElseThrow(() ->
                new RuntimeException("로그인 되어 있지 않은 사용자입니다."));
        refreshTokenRepository.delete(refreshToken);

        return "Success Logout";
    }

    private void setHeader(HttpServletResponse response, TokenDto tokenDto) {
        response.addHeader(JwtTokenUtil.ACCESS_TOKEN, tokenDto.getAccessToken());
        response.addHeader(JwtTokenUtil.REFRESH_TOKEN, tokenDto.getRefreshToken());
    }

}
