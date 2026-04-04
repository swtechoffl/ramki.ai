const Datastore = require('@seald-io/nedb');
const bcrypt = require('bcryptjs');
const path = require('path');

const db = new Datastore({ filename: path.join(__dirname, 'data', 'users.db'), autoload: true });

const NEW_PASSWORD = 'Admin@1234';
const hash = bcrypt.hashSync(NEW_PASSWORD, 12);

// Remove all existing users first, then insert fresh
db.remove({}, { multi: true }, (err) => {
  if (err) { console.error('Remove failed:', err); process.exit(1); }

  db.insert({ username: 'ramki', password: hash, role: 'admin', createdAt: new Date() }, (err2, doc) => {
    if (err2) { console.error('Insert failed:', err2); process.exit(1); }

    // Force write to disk
    db.persistence.compactDatafile();
    setTimeout(() => {
      console.log('✅ Done! User inserted:', doc._id);
      console.log('   Username: ramki');
      console.log('   Password: ' + NEW_PASSWORD);
      process.exit(0);
    }, 1000);
  });
});
