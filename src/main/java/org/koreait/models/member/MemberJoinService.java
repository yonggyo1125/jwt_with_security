package org.koreait.models.member;

import lombok.RequiredArgsConstructor;
import org.koreait.api.members.dto.RequestJoin;
import org.koreait.api.members.validator.JoinValidator;
import org.koreait.commons.constants.MemberType;
import org.koreait.entities.Member;
import org.koreait.repositories.MemberRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.validation.Errors;

@Service
@RequiredArgsConstructor
public class MemberJoinService {
    private final MemberRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JoinValidator validator;

    public void save(RequestJoin join, Errors errors) {
        validator.validate(join, errors);
        if (errors.hasErrors()) {
            return;
        }

        save(join);
    }

    public void save(RequestJoin join) {
        String password = passwordEncoder.encode(join.password());
        Member member = Member.builder()
                .email(join.email())
                .password(password)
                .name(join.name())
                .mobile(join.mobile())
                .type(MemberType.USER)
                .build();
        save(member);
    }

    public void save(Member member) {
        System.out.println(member);
        repository.saveAndFlush(member);
    }
}
