const db = {
  query(_query) {
    return [];
  },
};

function runQuery(name) {
  return db.query("SELECT * FROM users WHERE name = '" + name + "'");
}

module.exports = { runQuery };
