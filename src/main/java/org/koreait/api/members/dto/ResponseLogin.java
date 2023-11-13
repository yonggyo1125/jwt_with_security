package org.koreait.api.members.dto;

import lombok.Builder;

@Builder
public record ResponseLogin(
    String accessToken
) {}
