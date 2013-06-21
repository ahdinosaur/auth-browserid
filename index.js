var resource = require('resource'),
    logger = resource.logger,
    http = resource.use('http'),
    auth = resource.use('auth'),
    user = resource.use('user'),
    browserid = resource.define('auth-browserid');

browserid.schema.description = "for integrating BrowserID authentication";

browserid.persist('memory');

// .start() convention
function start(options, callback) {
  var async = require('async');

  //
  // setup auth provider
  //
  async.parallel([
    // setup .view convention
    function(callback) {
      var view = resource.use('view');
      view.create({ path: __dirname + '/view' }, function(err, _view) {
          if (err) { return callback(err); }
          browserid.view = _view;
          return callback(null);
      });
    },
    // start auth with browserid
    function(callback) {
      auth.start({provider: browserid}, callback);
    },
    // use auth strategy of provider
    function(callback) {
      browserid.strategy(function(err, strategy) {
        if (err) { return callback(err); }
        auth.use(strategy, callback);
      });
    },
    // use route of provider
    function(callback) {
      browserid.routes({}, callback);
    }],
  function(err, results) {
    return callback(err);
  });
}
browserid.method('start', start, {
  description: "starts browserid"
});

browserid.property('id', {
  description: 'email of browserid auth'
});

function strategy(callback) {
  var BrowserIDStrategy = require('passport-browserid').Strategy,
      async = require('async');
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
        async.waterfall([
          // get browserid instance
          function(callback) {
            browserid.get(email, function(err, _browserid) {
              if (err && (err.message === email + " not found")) {
                logger.info("email not found. creating new browserid");
                browserid.create({
                  id: email
                }, function(err, _browserid) {
                  if (err) { return callback(err); }
                  logger.info("new browserid with id", _browserid.id, "created");
                  logger.info("new browserid object", JSON.stringify(_browserid));
                  return callback(null, _browserid);
                });
              } else if (err) {
                return callback(err);
              } else {
                return callback(null, _browserid);
              }
            });
          },
          // get user instance
          function(_browserid, callback) {
            logger.info("finding user with browserid email");
            user.find({browserid: _browserid.id}, function(err, _users) {
              if (err) { return callback(err); }
              else if (_users.length > 1) {
                logger.info("multiple users with same browserid id found!");
                // TODO merge multiple users with same browserid into one
                return callback(null, _user[0]);
              } else if (_users.length === 0) {
                logger.info("user not found, creating new user");
                user.create({browserid: _browserid.id}, function(err, _user) {
                  if (err) { return callback(err); }
                  logger.info("new user with id", _user.id, "created");
                  logger.info("new user object", JSON.stringify(_user));
                  return callback(null, _user);
                });
              } else {
                logger.info("using existing user", _users[0].id);
                return callback(null, _users[0]);
              }
            });
          }],
          // return user as auth
          function(err, _user) {
            if (err) { return done(err); }
            return done(null, _user);
          });
      } else {
        logger.info('user is logged in, associating browserid with user');
        var _user = req.user;
        browserid.get(email, function(err, _browserid) {
          if (err && (err.message === email + " not found")) {
            logger.info("email not found. creating new browserid");
            browserid.create({
              id: email
            }, function(err, _browserid) {
              if (err) { return done(err); }
              logger.info("new browserid with id", _browserid.id, "created");
              logger.info("new browserid object", JSON.stringify(_browserid));
              // associate new browserid with user
              _user['browserid'] = _browserid.id;
              // preserve the login state by returning the existing user
              _user.save(done);
            });
          } else if (err) {
            return done(err);
          } else {
            logger.info("email found. using existing browserid");
            // associate new browserid with user
            _user['browserid'] = _browserid.id;
            // preserve the login state by returning the existing user
            _user.save(done);
          }
        });
      }
    });
  }));
}
browserid.method('strategy', strategy, {
  description: 'return BrowserID strategy'
});

function routes(options, callback) {
  http.app.post('/auth/browserid',
    auth.authenticate('browserid', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.redirect('/');
    });
  callback(null);
}
browserid.method('routes', routes, {
  description: 'sets routes for browserid in app'
});

browserid.dependencies = {
  'passport-browserid': '*',
  'async': '*'
};
browserid.license = 'MIT';
exports['auth-browserid'] = browserid;
