package com.higgsup.common.exceptions;

import org.springframework.http.HttpStatus;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class ErrorResponse {
    private final HttpStatus status;
    private final String message;
    private final ErrorCode errorCode;
    private final Date timestamp;
    private final Map<String, Object> additionalInfos = new HashMap<>();

    private ErrorResponse(String message, ErrorCode errorCode, HttpStatus status) {
        this.message = message;
        this.errorCode = errorCode;
        this.status = status;
        this.timestamp = new Date();
    }

    public static ErrorResponse of(String message, ErrorCode errorCode, HttpStatus status) {
        return new ErrorResponse(message, errorCode, status);
    }

    public ErrorResponse additionalInfo(String name, Object value) {
        this.additionalInfos.put(name, value);
        return this;
    }

    public Integer getStatus() {
        return status.value();
    }

    public String getMessage() {
        return message;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public Map<String, Object> getAdditionalInfos() {
        return additionalInfos;
    }
}
