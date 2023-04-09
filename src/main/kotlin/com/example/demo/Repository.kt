package com.example.demo

import com.example.demo.model.UserAuth
import org.springframework.data.mongodb.repository.MongoRepository
import org.springframework.stereotype.Repository

@Repository
interface UserRepository : MongoRepository<UserAuth, String> {
    fun findUserByEmail(email: String): UserAuth
    fun save(userAuth: UserAuth)
}
