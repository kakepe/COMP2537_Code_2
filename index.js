const fs = require('fs');
const path = require('path');

require("./utils.js");
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const {database} = require('./databaseConnection.js');

const app = express();
const saltRounds = 12;
const expireTime = 24 * 60 * 60 * 1000; // 1 day

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.NODE_SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    client: database,
    crypto: { secret: process.env.MONGODB_SESSION_SECRET }
  }),
  cookie: { maxAge: expireTime }
}));
app.use(express.static(__dirname + '/public'));

// View engine
app.set('view engine', 'ejs');

// Connect to Mongo and start server
async function main() {
  await database.connect();
  const db = database.db(process.env.MONGODB_DATABASE);
  const userCollection = db.collection('users');

  // Routes
/*  app.get('/', (req, res) => {
    if (!req.session.authenticated) {
      return res.render('index', { authenticated: false });
    }
    res.render('index', {
      authenticated: true,
      name: req.session.name,
      userType: req.session.user_type
    });
  });*/

  app.get('/', (req, res) => {
  // Grab these three straight from the session (or default to false/empty)
  const authenticated = req.session.authenticated || false;
  const name          = req.session.name          || '';
  const userType      = req.session.user_type     || '';

  // Pass them into the template!
  res.render('index', { authenticated, name, userType });
});

  app.get('/signup', (req, res) => {
    res.render('signup');
  });

  app.post('/submitUser', async (req, res) => {
    const schema = Joi.object({
      name: Joi.string().min(1).required(),
      email: Joi.string().email().required(),
      password: Joi.string().min(6).required()
    });
    const { error, value } = schema.validate(req.body);
    if (error) {
      return res.status(400).send(error.details[0].message);
    }
    const { name, email, password } = value;
    const existing = await userCollection.findOne({ email });
    if (existing) {
      return res.status(400).send('Email already in use');
    }
    const hashed = await bcrypt.hash(password, saltRounds);
    await userCollection.insertOne({
  name,
  email,
  password: hashed,
  user_type: 'admin'
});
req.session.authenticated = true;
    req.session.name = name;
    req.session.user_type = 'admin';
    res.redirect('/members');
  });

  app.get('/login', (req, res) => {
    res.render('login');
  });

  app.post('/loggingin', async (req, res) => {
    const schema = Joi.object({
      email: Joi.string().email().required(),
      password: Joi.string().min(6).required()
    });
    const { error, value } = schema.validate(req.body);
    if (error) {
      return res.status(400).send(error.details[0].message);
    }
    const { email, password } = value;
    const user = await userCollection.findOne({ email });
    if (!user) {
      return res.status(400).send('Invalid email or password');
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).send('Invalid email or password');
    }
    req.session.authenticated = true;
    req.session.name = user.name;
    req.session.user_type = user.user_type;
    res.redirect('/members');
  });

  app.get('/members', (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect('/');
  }

  // scan the public/images folder for image files
  const imagesDir = path.join(__dirname, 'public', 'images');
  let files = [];
  try {
    files = fs
      .readdirSync(imagesDir)
      .filter(f => /\.(jpe?g|png|gif)$/i.test(f));
  } catch (err) {
    console.error('Could not read images directory:', err);
  }

  // build the URLs (so that express.static will serve them)
  const images = files.map(f => `images/${f}`);

  res.render('members', {
    name: req.session.name,
    images
  });
});

// inside your async main() after you’ve set up userCollection:

// 7. Admin page – site: /admin method: GET
app.get('/admin', async (req, res) => {
  // if not logged in, send them to login
  if (!req.session.authenticated) {
    return res.redirect('/login');
  }
  // if logged in but not admin, show 403 error
  if (req.session.user_type !== 'admin') {
    return res.status(403).render('admin', {
      error: 'You are not authorized to view this page.',
      users: []
    });
  }
  // otherwise fetch all users and render
  const users = await userCollection.find().toArray();
  res.render('admin', {
    error: null,
    users
  });
});

app.get('/admin/promote', async (req, res) => {
  // guard
  if (!req.session.authenticated || req.session.user_type !== 'admin') {
    return res.redirect('/login');
  }
  await userCollection.updateOne(
    { email: req.query.email },
    { $set: { user_type: 'admin' } }
  );
  res.redirect('/admin');
});

app.get('/admin/demote', async (req, res) => {
  if (!req.session.authenticated || req.session.user_type !== 'admin') {
    return res.redirect('/login');
  }
  await userCollection.updateOne(
    { email: req.query.email },
    { $set: { user_type: 'user' } }
  );
  res.redirect('/admin');
});

  app.get('/logout', (req, res) => {
    req.session.destroy(() => {
      res.redirect('/');
    });
  });

  // 404 handler
  app.use((req, res) => {
    res.status(404).render('404');
  });

  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
  });
}

main().catch(err => console.error(err));
