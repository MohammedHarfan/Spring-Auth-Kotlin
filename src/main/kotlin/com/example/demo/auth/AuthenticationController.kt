package com.example.demo.auth

import com.example.demo.UserRepository
import com.example.demo.config.JwtUtil
import com.example.demo.model.*
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpHeaders
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.bind.annotation.*
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@RestController
class AuthenticationController {
    @Autowired
    private lateinit var authenticationManager: AuthenticationManager

    @Autowired
    private lateinit var passwordEncoder: PasswordEncoder

    @Autowired
    private lateinit var userDetailsService: AuthenticationService

    @Autowired
    private lateinit var jwtUtil: JwtUtil

    @Autowired
    private lateinit var userRepository: UserRepository

    @GetMapping("/hello")
    fun hello(): String {
        return "Harfan here"
    }

    @GetMapping("/checkUser")
    fun checkUser(): String {
        val authentication =
            SecurityContextHolder.getContext().authentication
        return authentication.name
    }

    @PostMapping("/authenticate")
    fun authenticate(@RequestBody authenticationRequest: AuthenticationRequest): ResponseEntity<*> {
        authenticationManager.authenticate(
            UsernamePasswordAuthenticationToken(
                authenticationRequest.username,
                authenticationRequest.password
            )
        )
        val userDetails: UserDetails = authenticationRequest.username.let { userDetailsService.loadUserByUsername(it) }!!
        val jwt = jwtUtil.generateToken(userDetails)
        return ResponseEntity.ok<Any>(AuthenticationResponse(jwt))
    }

    @PostMapping("/signin")
    fun authenticateUser(@RequestBody loginRequest: LoginRequest): ResponseEntity<*> {
        val authentication = authenticationManager.authenticate(
            UsernamePasswordAuthenticationToken(
                loginRequest.email,
                loginRequest.password
            )
        )
        SecurityContextHolder.getContext().authentication = authentication
        val userDetails: UserDetails = userDetailsService.loadUserByUsername(loginRequest.email)!!
        val jwt = jwtUtil.generateToken(userDetails)
        val responseBody = AuthenticationResponse(loginRequest.email)
        val responseHeaders = HttpHeaders()
        responseHeaders.add("Authorization", jwt)
        return ResponseEntity.ok().headers(responseHeaders).body(responseBody)
    }


    @PostMapping("/signup")
    fun registerUser(@RequestBody signUpRequest: SignUpRequest): ResponseEntity<*> {
        // Creating user's account
        val jwtUser = UserAuth(null, signUpRequest.email, passwordEncoder.encode(signUpRequest.password))

        println("jwtUser >> " + jwtUser.email)
        jwtUser.let { userRepository.save(it) }
        return ResponseEntity.ok<Any>(ApiResponse(true, "User registered successfully"))
    }

    @PostMapping("/logout-user")
    fun logout(@RequestHeader("Authorization") authorizationHeader: String): ResponseEntity<String> {
        val jwtToken = authorizationHeader.substring(7)
        jwtUtil.invalidateToken(jwtToken)
        return ResponseEntity.ok("Logged out successfully.")
    }
}