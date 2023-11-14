package org.koreait.commons.validators;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public interface PasswordValidator {
    /**
     * 비밀번호 복잡성 체크 - 알파벳 체크
     *
     * @param password
     * @param caseIncentive
     *          false : 소문자 + 대문자가 반드시 포함되는 패턴
     *          true : 대소문자 상관없이 포함되는 패턴
     * @return
     */
    default boolean alphaCheck(String password, boolean caseIncentive) {
        if (caseIncentive) { // 대소문자 구분없이 체크
            Pattern pattern = Pattern.compile("[a-z]+", Pattern.CASE_INSENSITIVE);
            return pattern.matcher(password).find();
        }

        // 대문자, 소문자 각각 체크
        Pattern pattern1 = Pattern.compile("[a-z]+");
        Pattern pattern2 = Pattern.compile("[A-Z]+");
        return pattern1.matcher(password).find() && pattern2.matcher(password).find();
    }
    /**
     * 숫자가 포함된 패턴인지 체크
     *
     * @param password
     * @return
     */
    default boolean numberCheck(String password) {
        Pattern pattern = Pattern.compile("\\d+");
        Matcher matcher = pattern.matcher(password);
        return matcher.find();
    }

    /**
     * 특수문자가 포함된 패턴인지 체크
     * @param password
     * @return
     */
    default boolean specialCharsCheck(String password) {
        Pattern pattern = Pattern.compile("[`~!#$%\\^&\\*()-_+=]+");
        Matcher matcher = pattern.matcher(password);
        return matcher.find();
    }
}
