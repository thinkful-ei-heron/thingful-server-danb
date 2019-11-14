function requireAuth(req, res, next) {
  let basicToken;
  const authToken = req.get('authorization')
  if(!authToken) return res.json({error: "auth"})
  if(!authToken.toLowerCase().split(' ')[0] === 'basic'){
    return res.json({error: 'Missing basic token'})
  } else {
    basicToken = authToken.split(' ')[1]
  }
  const [tokenUserName, tokenPassword] = Buffer
    .from(basicToken, 'base64')
    .toString()
    .split(':')
  if(!tokenUserName || !tokenPassword) {
   return res.json({error: 'Unauth request'})
   }
  req.app.get('db')("thingful_users")
    .where({user_name: tokenUserName})
    .first()
    .then(user => {
      if(!user || user.password !== tokenPassword) {
        return res.status(401).json({error: "Unauthorized access"})
      }
      req.user = user;
    next()
    })
    .catch(next)
}

module.exports = {
  requireAuth
}
