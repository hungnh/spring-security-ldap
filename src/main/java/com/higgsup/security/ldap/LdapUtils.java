package com.higgsup.security.ldap;

import org.apache.directory.api.util.DateUtils;
import org.springframework.ldap.core.DirContextOperations;

import java.text.ParseException;
import java.util.Date;

public class LdapUtils {

    public static final String LAST_PASSWORD_RESET_DATE_ATTRIBUTE_NAME = "pwdLastSet";

    public static Date getLastPasswordResetDateFromContext(DirContextOperations userContext) {
        try {
            return DateUtils.convertIntervalDate(userContext.getStringAttribute(LAST_PASSWORD_RESET_DATE_ATTRIBUTE_NAME));
        } catch (ParseException e) {
            System.out.println("Failed to parse pwdLastSet attribute from context to Java Date. Cause: " + e);
        }
        return null;
    }
}
