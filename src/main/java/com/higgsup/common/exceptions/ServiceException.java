package com.higgsup.common.exceptions;

public abstract class ServiceException extends Exception {

    private static final long serialVersionUID = -2957454419919133949L;

    public ServiceException(String message) {
        super(message);
    }

    public ServiceException(String message, Throwable cause) {
        super(message, cause);
    }
}
