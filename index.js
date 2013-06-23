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
  return callback(null, new BrowserIDStrategy({
    audience: 'http://localhost:8888',
    passReqToCallback: true
  },
  function(req, email, done) {
    // asynchronous verification, for effect...
    process.nextTick(function () {
      async.waterfall([
        // get browserid instance, or create if not already exist
        function(callback) {
          browserid.get(email, function(err, _browserid) {
            if (err && (err.message === email + " not found")) {
              logger.info("browserid id", email, "not found. creating new browserid");
              browserid.create({
                id: email
              }, callback);
            } else if (err) {
              return callback(err);
            } else {
              logger.info("browserid id ", _browserid.id, "found");
              callback(null, _browserid);
            }
          });
        },
        // log browserid object
        function(_browserid, callback) {
          logger.info("browserid object", JSON.stringify(_browserid));
          callback(null, _browserid);
        },
        // associate browserid with user auth
        function(_browserid, callback) {
          var _user = req.user;
          if (!_user) {
            logger.info('user is not logged in');
            async.waterfall([
              // find auth instances with browserid id, or create none exist
              function(callback) {
                auth.find({browserid: _browserid.id}, function(err, _auths) {
                  if (err) { return callback(err); }
                  else if (_auths.length > 1) {
                    logger.info("multiple auths with same browserid id found!");
                    // TODO merge multiple auths with same browserid into one
                    return callback(null, _auth[0]);
                  } else if (_auths.length === 0) {
                    logger.info("browserid id", _browserid.id, "not found in any auth. creating new auth");
                    auth.create({browserid: _browserid.id}, callback);
                  } else {
                    logger.info("using existing auth", _auths[0].id);
                    return callback(null, _auths[0]);
                  }
                });
              },
              // log auth object
              function(_auth, callback) {
                logger.info("auth object", JSON.stringify(_auth));
                return callback(null, _auth);
              },
              // find user instance with auth id, or create if none exist
              function(_auth, callback) {
                logger.info("getting user with auth id");
                user.get(_auth.id, function(err, _user) {
                  if (err && (err.message === _auth.id + " not found")) {
                    logger.info("user id", _auth.id, "not found. creating new user");
                    user.create({id: _auth.id}, callback);
                  } else if (err) {
                    return callback(err);
                  } else {
                    logger.info("user id ", _user.id, "found");
                    callback(null, _user);
                  }
                });
              }],
              // return user object to top waterfall
              callback);
          } else {
            logger.info('user is logged in');
            auth.get(_user.id, function(err, _auth) {
              // TODO check for collisions here
              // associate browserid with auth
              _auth['browserid'] = _browserid.id;
              // save auth instance
              _auth.save(function(err, _auth) {
                if (err) { return callback(err); }
                // log auth object
                logger.info("auth object", JSON.stringify(_auth));
                // return user object to top waterfall
                return callback(null, _user);
              });
            });
          }
        }],
        // end top waterfall
        done);
    });
  }));
}
browserid.method('strategy', strategy, {
  description: 'return BrowserID strategy'
});

function routes(options, callback) {
  http.app.post('/auth/browserid',
    auth.authenticate('browserid', { failureRedirect: '/' }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.redirect('/');
    });
  return callback(null);
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
