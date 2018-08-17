package com.higgsup.security.ldap;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "com.higgsup.security.ldap")
public class LdapSettings {
    /**
     * Specifies the ldap server URL.
     * For example, "ldap://ldap.example.com:33389/dc=higgsup,dc=com".
     */
    private String url;

    /**
     * Username (DN) of the "manager" user identity (i.e. "uid=admin,ou=system") which
     * will be used to authenticate to a (non-embedded) LDAP server.
     */
    private String managerDn;

    /**
     * The password for the manager DN.
     * This is required if the manager-dn is specified.
     */
    private String managerPassword;

    /**
     * Search base for user searches.
     * Defaults to "".
     */
    private String userSearchBase = "";

    /**
     * The LDAP filter used to search for users (optional).
     * For example "(uid={0})".
     * The substituted parameter is the user's login name.
     */
    private String userSearchFilter = "(uid={0})";

    /**
     * The search base for group membership searches.
     * Defaults to "".
     */
    private String groupSearchBase = "";

    /**
     * Specifies the attribute name which contains the role name.
     * Default is "cn".
     */
    private String groupRoleAttribute = "cn";

    /**
     * The LDAP filter to search for groups.
     * Defaults to "(uniqueMember={0})".
     * The substituted parameter is the DN of the user.
     */
    private String groupSearchFilter = "(uniqueMember={0})";

    /**
     * A non-empty string prefix that will be added as a prefix to the existing roles.
     * Defaults to "ROLE_".
     */
    private String rolePrefix = "ROLE_";

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getManagerDn() {
        return managerDn;
    }

    public void setManagerDn(String managerDn) {
        this.managerDn = managerDn;
    }

    public String getManagerPassword() {
        return managerPassword;
    }

    public void setManagerPassword(String managerPassword) {
        this.managerPassword = managerPassword;
    }

    public String getUserSearchBase() {
        return userSearchBase;
    }

    public void setUserSearchBase(String userSearchBase) {
        this.userSearchBase = userSearchBase;
    }

    public String getUserSearchFilter() {
        return userSearchFilter;
    }

    public void setUserSearchFilter(String userSearchFilter) {
        this.userSearchFilter = userSearchFilter;
    }

    public String getGroupSearchBase() {
        return groupSearchBase;
    }

    public void setGroupSearchBase(String groupSearchBase) {
        this.groupSearchBase = groupSearchBase;
    }

    public String getGroupRoleAttribute() {
        return groupRoleAttribute;
    }

    public void setGroupRoleAttribute(String groupRoleAttribute) {
        this.groupRoleAttribute = groupRoleAttribute;
    }

    public String getGroupSearchFilter() {
        return groupSearchFilter;
    }

    public void setGroupSearchFilter(String groupSearchFilter) {
        this.groupSearchFilter = groupSearchFilter;
    }

    public String getRolePrefix() {
        return rolePrefix;
    }

    public void setRolePrefix(String rolePrefix) {
        this.rolePrefix = rolePrefix;
    }
}
