const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");

const initPassport = (passport, users) => {
  const verifyCallback = async (email, password, done) => {
    const user = users.find((user) => user.email === email);

    if (!user)
      return done(null, false, { message: "404 - No user was found." });

    try {
      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch)
        return done(null, false, { message: "Credentials incorrect!" });

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  };

  passport.use(
    new LocalStrategy(
      {
        usernameField: "email",
      },
      verifyCallback
    )
  );
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser((id, done) =>
    done(
      null,
      users.find((user) => user.id === id)
    )
  );
};

module.exports = initPassport;
