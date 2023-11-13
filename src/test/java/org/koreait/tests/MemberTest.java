package org.koreait.tests;

import org.junit.jupiter.api.Test;
import org.koreait.api.members.dto.RequestJoin;
import org.koreait.models.member.MemberJoinService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class MemberTest {

    @Autowired
    private MemberJoinService joinService;

    @Test
    public void insertData() {
        RequestJoin form =
                new RequestJoin(
                        "user01@test.org",
                        "12345678",
                        "12345678",
                        "사용자01",
                        "01010001000",
                        true);
        joinService.save(form);
    }
}
