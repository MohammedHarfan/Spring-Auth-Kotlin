package com.example.demo.model

import org.springframework.data.annotation.Id
import org.springframework.data.mongodb.core.mapping.Document


@Document("users-auth")
data class UserAuth(
    @Id
    val id: String?,
    var email: String,
    var password: String,
)

data class AuthenticationRequest(
    var username: String,
    var password: String
)

data class AuthenticationResponse(
    var username: String
)

data class LoginRequest(
    var email: String,
    var password: String
)

data class SignUpRequest(
    var email: String,
    var password: String
)

data class ApiResponse(
    var success: Boolean,
    var message:String
)