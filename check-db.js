const Datastore = require('nedb');
const bcrypt = require('bcryptjs');
const path = require('path');

const db = new Datastore({ filename: path.join(__dirname, 'data', 'users.db'), autoload: true });

db.find({}, (err, users) => {
  console.log('Users in DB:', JSON.stringify(users, null, 2));

  // Test password match
  users.forEach(u => {
    const match = bcrypt.compareSync('Admin@1234', u.password);
    console.log(`\nUser: ${u.username}, Password 'Admin@1234' matches: ${match}`);
  });
  process.exit(0);
});
