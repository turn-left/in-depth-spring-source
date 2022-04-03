package com.ethen.model;

import com.ethen.config.UserProperties;

public class UserClient {
    private UserProperties userProperties;

    public UserClient() {
    }

    public UserClient(UserProperties userProperties) {
        this.userProperties = userProperties;
    }

    public String getName() {
        return userProperties.getName();
    }

    public String getLogo() {
        return userProperties.getLogo();
    }
}
