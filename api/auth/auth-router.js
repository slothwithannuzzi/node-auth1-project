// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const express = require('express');
const router = express.Router();
const {checkUsernameFree, checkUsernameExists, checkPasswordLength} = require('../auth/auth-middleware');
const Users = require('../users/users-model')
const bcrypt = require('bcryptjs')

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
  router.post("/register", checkUsernameFree, checkPasswordLength, async (req,res)=>{
    try{
        const hash = bcrypt.hashSync(req.body.password, 10)
        const newUser = await Users.add({username: req.body.username, password: hash})
        res.status(201).json(newUser)
    }catch(e){
        res.status(500).json({message: e.message})
    }
})


/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */

  router.post("/login", checkUsernameExists, checkPasswordLength, async (req,res)=>{
    try{
        const verified = bcrypt.compareSync(req.body.password, req.userData.password)
        if(verified){
            req.session.user = req.userData
            res.json(`Welcome ${req.userData.username}`)
        } else{
            res.status(401).json("Invalid credentials")
        }
    }catch(e){
        res.status(500).json({message: e.message})
    }
})


/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
  router.get("/logout", (req,res)=>{
    if(req.session){
        req.session.destroy(err => {
            if(err){
                res.status(500).json({message: "Can't log out"})
            } else{
                res.status(200).json({message: "logged out"})
            }
        })
    } else{
        res.status(200).json({message:"No session"})
    }
})

 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;