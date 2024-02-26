package com.team.leaf.user.account.controller;

import com.team.leaf.user.account.dto.request.UpdateAccountDto;
import com.team.leaf.user.account.dto.response.AccountDto;
import com.team.leaf.user.account.exception.ApiResponse;
import com.team.leaf.user.account.service.AccountService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequiredArgsConstructor
@RequestMapping("/account/mypage")
public class AccountPageController {

    private final AccountService accountService;

    //유저 정보 조회
    @GetMapping("/{email}")
    public ApiResponse<AccountDto> getAccount(@PathVariable String email) {
        AccountDto accountDto = accountService.getUser(email);

        return new ApiResponse<>(accountDto);
    }

    //유저 정보 수정
    @PutMapping("/{email}/update")
    public ApiResponse<String> updateAccount(@PathVariable String email, UpdateAccountDto accountDto) throws IOException {
        return new ApiResponse<>(accountService.updateUser(email,accountDto));
    }

}

