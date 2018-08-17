package com.higgsup.security.config;

import com.higgsup.security.ldap.LdapSettings;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;

@Configuration
public class LdapConfig {

    private final LdapSettings ldapSettings;

    public LdapConfig(LdapSettings ldapSettings) {
        this.ldapSettings = ldapSettings;
    }

    @Bean
    public LdapContextSource ldapContextSource() {
        LdapContextSource contextSource = new DefaultSpringSecurityContextSource(ldapSettings.getUrl());
        contextSource.setUserDn(ldapSettings.getManagerDn());
        contextSource.setPassword(ldapSettings.getManagerPassword());
        return contextSource;
    }

    @Bean
    public LdapAuthoritiesPopulator ldapAuthoritiesPopulator() {
        DefaultLdapAuthoritiesPopulator ldapAuthoritiesPopulator
                = new DefaultLdapAuthoritiesPopulator(ldapContextSource(), ldapSettings.getGroupSearchBase());
        ldapAuthoritiesPopulator.setGroupRoleAttribute(ldapSettings.getGroupRoleAttribute());
        ldapAuthoritiesPopulator.setGroupSearchFilter(ldapSettings.getGroupSearchFilter());
        ldapAuthoritiesPopulator.setRolePrefix(ldapSettings.getRolePrefix());
        return ldapAuthoritiesPopulator;

    }

    @Bean
    public LdapUserSearch ldapUserSearch() {
        return new FilterBasedLdapUserSearch(
                ldapSettings.getUserSearchBase(),
                ldapSettings.getUserSearchFilter(),
                ldapContextSource()
        );
    }

    @Bean
    public LdapUserDetailsMapper ldapUserDetailsMapper() {
        return new LdapUserDetailsMapper();
    }

}
