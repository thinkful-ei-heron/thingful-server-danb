function requireAuth(req, res, next) {
  let basicToken;
  const authToken = req.get('Authorization');
  if (!authToken) return res.json({error: 'auth'});
  if (!authToken.toLowerCase().startsWith('basic ')) {
    return res.status(401).json({error: 'Missing basic token'});
  } else {
    basicToken = authToken.slice('basic '.length, authToken.length);
  }
  const [tokenUserName, tokenPassword] = Buffer.from(basicToken, 'base64')
    .toString()
    .split(':');
  if (!tokenUserName || !tokenPassword) {
    return res.json({error: 'Unauth request'});
  }
  req.app
    .get('db')('thingful_users')
    .where({user_name: tokenUserName})
    .first()
    .then(user => {
      if (!user || user.password !== tokenPassword) {
        return res.status(401).json({error: 'Unauthorized access'});
      }
      req.user = user;
      next();
    })
    .catch(next);
}

module.exports = {
  requireAuth,
};
