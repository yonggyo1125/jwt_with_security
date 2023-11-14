package org.koreait.commons;

import org.springframework.validation.Errors;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.ResourceBundle;

public class Utils {
    private static ResourceBundle validationsBundle;
    private static ResourceBundle errorsBundle;

    static {
        validationsBundle = ResourceBundle.getBundle("messages.validations");
        errorsBundle = ResourceBundle.getBundle("messages.errors");
    }

    public static String getMessage(String code, String bundleType) {
        bundleType = Objects.requireNonNullElse(bundleType, "validation");
        ResourceBundle bundle = bundleType.equals("error")? errorsBundle:validationsBundle;
        try {
            return bundle.getString(code);
        } catch (Exception e) {
            return null;
        }
    }

    public static List<String> getMessages(Errors errors) {
        return errors.getFieldErrors().stream().map(f -> Arrays.stream(f.getCodes()).map(c -> getMessage(c + "." + f.getField(), "validation")))
                .flatMap(s -> s)
                .filter(s -> s != null && !s.isBlank()).toList();
    }
}
