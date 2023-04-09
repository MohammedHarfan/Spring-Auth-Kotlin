package com.example.demo.auth

import com.example.demo.UserRepository
import com.example.demo.model.UserAuth
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service


@Service
class AuthenticationService : UserDetailsService {
    @Autowired
    var jwtUserRepository: UserRepository? = null

    @Throws(UsernameNotFoundException::class)
    override fun loadUserByUsername(email: String): UserDetails? {
        val user: UserAuth = jwtUserRepository!!.findUserByEmail(email)
        return org.springframework.security.core.userdetails.User(user.email, user.password, ArrayList())
    }
}