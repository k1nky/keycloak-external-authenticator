package dev.k1nky.keycloak.authentication.authenticator;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonProperty;


/**
 * @author Andrey Shalashov, https://github.com/k1nky, @k1nky
 */
public class UserDto {

    public UserDto(List<String> groups, List<String> roles, Map<String, String> attributes) {
        this.groups = groups;
        this.roles = roles;
        this.attributes = attributes;
    }

    @JsonProperty("groups")
    private List<String> groups;

    @JsonProperty
    private List<String> roles;

    @JsonProperty
    private Map<String, String> attributes;
}
