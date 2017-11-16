const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const serviceAuth = require('../service/auth')

passport.serializeUser((user, done) => {
  done(null, user.id)
})

passport.deserializeUser(async(id, done) => {
  const user = await serviceAuth.findById(id)
  done(null, user)
})

// Sign in with username and Password
passport.use('local', new LocalStrategy({
  usernameField: 'username',
}, async(username, password, done) => {
  const user = await serviceAuth.signin(username, password)
  done(null, user)
}))


/**
 * Login Required middleware.
 */
exports.isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    res.locals.user = req.session.user
    console.log('passport: ' + res.locals.user)
    return next()
  }
  res.redirect('login')
}
