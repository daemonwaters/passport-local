const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const users = require("./model/users");
const initPassport = require("./config/passport.config");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
const checkIsAuthenticated = require("./middleware/checkIsAuthenticated");
const checkIsLoggedIn = require("./middleware/checkIsLoggedIn");
const override = require("method-override");
const PORT = process.env.PORT || 3500;
require("dotenv").config();
const MongoStore = require("connect-mongo");
const errorHandler = require("./middleware/errorHandler");

initPassport(passport, users);

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(
  session({
    secret: process.env.SECRET,
    resave: true,
    saveUninitialized: true,
    store: new MongoStore({
      collectionName: "mydocs",
      mongoUrl: process.env.DB_URI,
    }),
    cookie: {
      maxAge: 15 * 1000,
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(override("_method"));

app.get("/", checkIsAuthenticated, (req, res) => {
  res.render("index.ejs", { name: req.user.name });
});

app.post("/register", async (req, res, next) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    users.push({
      id: Date.now().toString(),
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword,
    });

    res.redirect("/login");
  } catch (err) {
    next(err);
    res.redirect("/register");
  }
});

app.get("/register", checkIsLoggedIn, (req, res) => {
  res.render("register.ejs");
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true,
  })
);

app.get("/login", checkIsLoggedIn, (req, res) => {
  res.render("login.ejs");
});

app.delete("/logout", (req, res, next) => {
  req.logOut((err) => {
    if (err) return next(err);
    res.redirect("/login");
  });
});

app.use(errorHandler);

app.listen(
  PORT,
  console.log(`Server up and running on http://localhost:${PORT}`)
);
