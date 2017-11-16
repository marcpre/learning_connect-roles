require('dotenv').config()
const passport = require('passport')
const session = require('express-session')
const ConnectRoles = require('connect-roles')
const express = require('express')

const app = express()

const user = new ConnectRoles({
  failureHandler (req, res, action) {
    // optional function to customise code that runs when
    // user fails authorisation
    const accept = req.headers.accept || ''
    res.status(403)
    if (~accept.indexOf('html')) {
      res.render('access-denied', { action })
    } else {
      res.send(`Access Denied - You don't have permission to: ${action}`)
    }
  },
})

app.use(authentication)
app.use(user.middleware())

// anonymous users can only access the home page
// returning false stops any more rules from being
// considered
user.use((req, action) => {
  if (!req.isAuthenticated()) return action === 'access home page'
})

// moderator users can access private page, but
// they might not be the only ones so we don't return
// false if the user isn't a moderator
user.use('access private page', (req) => {
  if (req.user.role === 'moderator') {
    return true
  }
})

// admin users can access all pages
user.use((req) => {
  if (req.user.role === 'admin') {
    return true
  }
})

// Routes
app.get('/', user.can('access home page'), (req, res) => {
  res.render('private')
})
app.get('/private', user.can('access private page'), (req, res) => {
  res.render('private')
})
app.get('/admin', user.can('access admin page'), (req, res) => {
  res.render('admin')
})

// Services
const port = process.env.APP_PORT || 8080
const host = process.env.APP_HOST || 'localhost'

app.listen(port, () => {
  console.log(`Listening on ${host}:${port}`)
})

module.exports = app
