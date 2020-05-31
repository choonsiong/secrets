//jshint esversion:6

//require('dotenv').config();

//const md5 = require("md5");
// const encrypt = require("mongoose-encryption");

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");

const mongoose = require("mongoose");
const findOrCreate = require("mongoose-findorcreate");

// Authentication using Passport
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

// Passport's OAuth
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const TwitterStrategy = require("passport-twitter").Strategy;

const app = express();

//const bcrypt = require("bcrypt");
//const saltRounds = 10;
// const saltRounds = 21;

app.use(express.static("public"));

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));

// passport

app.use(session({
  secret: "iloveyou",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());

app.use(passport.session());

// mongodb

//mongoose.connect("mongodb://localhost:27017/secretUserDB", { useNewUrlParser: true, useUnifiedTopology: true });

const atlasUrl = "mongodb+srv://admin_secrets:" + process.env.ATLAS_PASSWORD + "@cluster0-jqho5.mongodb.net/secretsDB"
console.log(atlasUrl);
mongoose.connect(atlasUrl, { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  twitterId: String,
  secret: String
});

// userSchema.plugin(encrypt, {secret: process.env.SECRET_KEY, encryptedFields: ['password']});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

//passport.serializeUser(User.serializeUser());
//passport.deserializeUser(User.deserializeUser());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

// Google

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_OAUTH_CLIENT_ID,
    clientSecret: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
    callbackURL: "https://pure-lake-05784.herokuapp.com/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);

    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Facebook

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "https://pure-lake-05784.herokuapp.com/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);

    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Twitter

passport.use(new TwitterStrategy({
    consumerKey: process.env.TWITTER_API_KEY,
    consumerSecret: process.env.TWITTER_API_TOKEN,
    callbackURL: "https://pure-lake-05784.herokuapp.com/auth/twitter/secrets"
  },
  function(token, tokenSecret, profile, cb) {
    console.log(profile);

    User.findOrCreate({ twitterId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// routes

app.get("/", function(req, res) {
  res.render('home');
});

app.get("/login", function(req, res) {
  res.render('login');
});

// Google

app.get("/auth/google", passport.authenticate("google", { scope: ["profile"]}));

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

// Facebook

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

// Twitter

app.get('/auth/twitter',
  passport.authenticate('twitter'));

app.get('/auth/twitter/secrets',
  passport.authenticate('twitter', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });


//

app.post("/login", function(req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login_old", function(req, res) {
  const username = req.body.username;
  // const password = md5(req.body.password);
  const password = req.body.password;

  User.findOne({
    email: username
  }, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/");
    } else {
      if (user) {
        // if (user.password === password) {
        //   res.render("secrets");
        // }
        bcrypt.compare(password, user.password, function(err, result) {
          if (result === true) {
            res.render("secrets");
          }
        });
      }
    }
  });
});

app.get("/register", function(req, res) {
  res.render('register');
});

app.post("/register", function(req, res) {
  User.register(
    {
      username: req.body.username
    },
    req.body.password, function(err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function() {
          res.redirect("/secrets");
        });
      }
    });
});

app.post("/register_old", function(req, res) {
  // const newUser = new User({
  //   email: req.body.username,
  //   password: md5(req.body.password)
  // });
  //
  // newUser.save(function(err) {
  //   if (err) {
  //     console.log(err);
  //   } else {
  //     res.render("secrets");
  //   }
  // });

  bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    const newUser = new User({
      email: req.body.username,
      password: hash
    });

    newUser.save(function(err) {
      if (err) {
        console.log(err);
      } else {
        res.render("secrets");
      }
    });
  })
});

app.get("/submit", function(req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res) {
  const submittedSecret = req.body.secret;

  if (submittedSecret == "") {
    res.redirect("/submit");
  } else {
    console.log(req.user.id);

    User.findById(req.user.id, function(err, user) {
      if (err) {
        console.log(err);
      } else {
        if (user) {
          user.secret = submittedSecret;
          user.save(function() {
            res.redirect("/secrets");
          });
        }
      }
    });
  }
});

app.get("/secrets", function(req, res) {
  let userIsAuthenticated = false;
  if (req.isAuthenticated()) {
    //res.render("secrets");
    userIsAuthenticated = true;
  } else {
    //res.redirect("/login");
    userIsAuthenticated = false;
  }
  User.find({
    "secret": {$ne: null}
  }, function(err, users) {
    if (err) {
      console.log(err);
    } else {
      if (users) {
        res.render("secrets", {usersWithSecrets: users, userIsAuthenticated: userIsAuthenticated})
      }
    }
  });
});

app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
});

let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}

app.listen(port, function() {
  console.log("Server started successfully.");
});
