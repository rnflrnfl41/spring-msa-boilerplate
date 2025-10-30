package com.example.http;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum CustomHttpStatus {

    RETRY_WITH(449, "Retry With"),
    TOO_EARLY(425, "Too Early"),
    TOKEN_EXPIRED(498, "Invalid or Expired Token"),
    CLIENT_CLOSED_REQUEST(499, "Client Closed Request");

    private final int code;
    private final String reason;

}
