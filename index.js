var resource = require('resource'),
    logger = resource.logger,
    http = resource.use('http'),
    auth = resource.use('auth'),
    browserid = resource.define('auth-browserid');

browserid.schema.description = "for integrating BrowserID authentication";

browserid.persist('memory');

browserid.property('email', {
  description: 'email of browserid auth'
});

function strategy(callback) {
  BrowserIDStrategy = require('passport-browserid').Strategy;
  // Use the BrowserIDStrategy within Passport.
  //   Strategies in passport require a `validate` function, which accept
  //   credentials (in this case, a BrowserID verified email address), and invoke
  //   a callback with a user object.
  callback(null, new BrowserIDStrategy({
    audience: 'http://localhost:8888',
    passReqToCallback: true
  },
  function(req, email, done) {
    // asynchronous verification, for effect...
    process.nextTick(function () {
      if (!req.user) {
        logger.info('user is not logged in, authorizing with browserid');
        browserid.find({email: email}, function(err, browserids) {
          if (err) { throw err; }
          if (browserids.length === 0) {
            logger.info("email not found. creating new browserid");
            browserid.create({email: email}, function(err, _browserid) {
              if (err) { throw err; }
              logger.info("new browserid with id", _browserid.id, "created");
              logger.info("since new browserid, creating new user");
              auth.create({browserid: _browserid.id}, function(err, _auth) {
                if (err) { throw err; }
                logger.info("new user with id", _auth.id, "created");
                done(null, _auth);
              });
            });
          } else if (browserids.length > 1) {
            throw "multiple browserids with same email!";
          } else {
            logger.info("email found, using associated browserid");
            auth.find({browserid: browserids[0].id}, function(err, _auth) {
              if (err) { throw err; }
              done(null, _auth);
            });
          }
        });
      } else {
        logger.info('user is logged in, associating browserid with user');
        var user = req.user;
        browserid.find({email: email}, function(err, browserids) {
          if (err) { throw err; }
          if (browserids.length === 0) {
            logger.info("email not found. creating new browserid");
            browserid.create({email: email}, function(err, _browserid) {
              logger.info("new browserid with id", _browserid.id, "created");
              if (err) { throw err; }
              // associate new browserid with user
              user['browserid'] = _browserid.id;
              // preserve the login state by returning the existing user
              done(null, user);
            });
          } else if (browserids.length > 1) {
            throw "multiple browserids with same email!";
          } else {
            logger.info("email found. using existing browserid");
            // associate new browserid with user
            user['browserid'] = _browserid.id;
            // preserve the login state by returning the existing user
            done(null, user);
          }
        });
      }
    });
  }));
}
browserid.method('strategy', strategy, {
  description: 'return BrowserID strategy'
});

function routes() {
  var authOrAuthz = function(req, res, next) {
    if (!req.isAuthenticated) {
      auth.authenticate('browserid', { failureRedirect: '/login' })(req, res, next);
    } else {
      auth.authorize('browserid')(req, res, next);
    }
  };
  http.app.post('/auth/browserid', authOrAuthz);
  http.app.get('/test', function(req, res) {
    var body = 'Hello World';
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Content-Length', body.length);
    res.end(body);
  });
}
browserid.method('routes', routes, {
  description: 'sets routes for browserid in app'
});

browserid.dependencies = {
  'passport-browserid': '*'
};
browserid.license = 'MIT';
exports['auth-browserid'] = browserid;
