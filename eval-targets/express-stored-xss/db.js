module.exports = {
  async query(_sql) {
    return [{ bio: "stored profile" }];
  },
};
