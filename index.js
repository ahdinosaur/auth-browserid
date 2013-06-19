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

  // setup .view convention
  var view = resource.use('view');
  view.create({ path: __dirname + '/view' }, function(err, _view) {
      if (err) { return callback(err); }
      browserid.view = _view;
      return callback(null);
  });

  // setup auth provider
  async.parallel([
    // start auth with browserid
    function(callback) {
      auth.start({provider: browserid}, callback);
    },
    function(callback) {
      // use auth strategy of provider
      browserid.strategy(function(err, strategy) {
        if (err) { return callback(err); }
        auth.use(strategy, callback);
      });
    },
    // use route of provider
    function(callback) {
      browserid.routes({}, callback);
    }],
  function(err) {
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
        browserid.get(email, function(err, _browserid) {
          if (err && (err.message === email + " not found")) {
            logger.info("email not found. creating new browserid");
            browserid.create({id: email}, function(err, _browserid) {
              if (err) { return callback(err); }
              logger.info("new browserid with id", _browserid.id, "created");
              logger.info("since new browserid, creating new user");
              user.create({browserid: _browserid.id}, function(err, _user) {
                if (err) { return callback(err); }
                logger.info("new user with id", _user.id, "created");
                logger.info("new user object", JSON.stringify(_user));
                return done(null, _user);
              });
            });
          } else if (err) {
            return callback(err);
          } else {
            logger.info("email found, using associated browserid");
            logger.info("browserid objects found", JSON.stringify(browserids));
            user.find({browserid: _browserid.id}, function(err, _users) {
              if (err) { return callback(err); }
              if (_users.length > 1) {
                // TODO merge multiple users with same browserid into one
                return done(null, _user[0]);
              }
            });
          }
        });
      } else {
        logger.info('user is logged in, associating browserid with user');
        var _user = req.user;
        browserid.get(email, function(err, _browserid) {
          if (err && (err.message === email + " not found")) {
            logger.info("email not found. creating new browserid");
            browserid.create({email: email}, function(err, _browserid) {
              logger.info("new browserid with id", _browserid.id, "created");
              if (err) { return callback(err); }
              // associate new browserid with user
              _user['browserid'] = _browserid.id;
              // preserve the login state by returning the existing user
              _user.save(done);
            });
          } else if (err) {
            return callback(err);
          } else {
            logger.info("email found. using existing browserid");
            // associate new browserid with user
            _user['browserid'] = _browserid.id;
            // preserve the login state by returning the existing user
            done(null, _user);
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
  var authOrAuthz = function(req, res, next) {
    if (!req.isAuthenticated()) {
      auth.authenticate('browserid', {
        successRedirect: '/',
        failureRedirect: '/'
      })(req, res, next);
    } else {
      auth.authorize('browserid')(req, res, next);
    }
  };
  http.app.post('/auth/browserid', authOrAuthz);
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
