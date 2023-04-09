const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const Schema = mongoose.Schema;

const userSchema = new Schema({
  userName: {
    type: String,
    unique: true,
  },
  password: String,
  email: String,
  loginHistory: [
    {
      dateTime: Date,
      userAgent: String,
    },
  ],
});

let User; // to be defined on new connection (see initialize)

module.exports.initialize = function () {
  return new Promise(function (resolve, reject) {
    const connectionString = "mongodb://localhost:27017/web322db";
    const db = mongoose.createConnection(connectionString);

    db.on("error", (err) => {
      reject(err);
    });
    db.once("open", () => {
      User = db.model("users", userSchema);
      resolve();
    });
  });
};

/**
 *
 * @param {object} userData
 * @returns promise
 */
module.exports.registerUser = function (userData) {
  return new Promise(function (resolve, reject) {
    if (userData.password !== userData.password2) {
      reject("Passwords do not match");
    } else {
      bcrypt
        .hash(userData.password, 10)
        .then((hash) => {
          userData.password = hash;

          User.create(userData)
            .then(() => {
              resolve();
            })
            .catch((err) => {
              if (err.code === 11000) {
                reject("User Name already taken");
              } else {
                reject(`There was an error creating the user: ${err}`);
              }
            });
        })
        .catch(() => {
          reject("There was an error encrypting the password");
        });
    }
  });
};

module.exports.checkUser = function (userData) {
  return new Promise(function (resolve, reject) {
    User.find({ userName: userData.userName })
      .then((users) => {
        if (users.length === 0) {
          reject(`Unable to find user: ${userData.userName}`);
        } else {
          const user = users[0];
          bcrypt.compare(userData.password, user.password).then((result) => {
            if (result === true) {
              user.loginHistory.push({
                dateTime: new Date().toString(),
                userAgent: userData.userAgent,
              });

              User.updateOne(
                { userName: user.userName },
                {
                  $set: {
                    loginHistory: user.loginHistory,
                  },
                }
              )
                .then(() => resolve(user))
                .catch((err) => {
                  reject(`There was an error saving the login history: ${err}`);
                });
            } else {
              reject(`Incorrect Password for user: ${userData.userName}`);
            }
          });
        }
      })
      .catch((err) => {
        reject(`There was an error finding the user: ${err}`);
      });
  });
};
