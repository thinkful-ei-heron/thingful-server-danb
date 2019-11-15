const bcrypt = require('bcryptjs')

function requireAuth(req, res, next) {
  let basicToken;
  // Grab auth from http request
  const authToken = req.get('Authorization');
  if (!authToken) return res.json({error: 'auth'});
  if (!authToken.toLowerCase().startsWith('basic ')) {
    return res.status(401).json({error: 'Missing basic token'});
  } else {
    basicToken = authToken.slice('basic '.length, authToken.length);
  }
  // Return 'base64' encoded sting of authToken

  // Converting basicToken into user and passeword
  const [tokenUserName, tokenPassword] = Buffer.from(basicToken, 'base64')
    .toString()
    .split(':');
  // Check to see if the decoded basicToken has a user and password
  if (!tokenUserName || !tokenPassword) {
    return res.json({error: 'Unauth request'});
  }
  req.app('db')('thingful_users')
    .where({user_name: tokenUserName})
    .first()
    .then(user => {
      if(!user) return res.status(401).json({error: 'Unauthorized access'}) 
      return bcrypt.compare(tokenPassword, user.password)
        .then(passwordsMatch => {
          if (!passwordsMatch) {
            return res.status(401).json({error: 'Unauthorized access'}) 
          }
          req.user = user
          next()
        })
    })
}

module.exports = {
  requireAuth,
};
