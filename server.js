
const express = require('express');
const path = require('path');
const session = require('express-session');
const exphbs = require('express-handlebars');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 4111; // fix port issue 

// Trust proxy (required for correct IP logging and secure cookies behind Nginx/NPM)
app.set('trust proxy', true);

// middleware 
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(
  session({
    secret: 'this-is-intentionally-insecure',
    resave: false,
    saveUninitialized: true,
  })
);

app.engine(
  'handlebars',
  exphbs.engine({
    defaultLayout: 'main',
    layoutsDir: path.join(__dirname, 'views', 'layouts'),
    partialsDir: path.join(__dirname, 'views', 'partials'),
  })
);
app.set('view engine', 'handlebars');
app.set('views', path.join(__dirname, 'views'));

// make the user available to ALL views
app.use((req, res, next) => {
  res.locals.currentUser = req.session.username || null;
  next();
});

// show home page
app.get('/', (req, res) => {
  res.render('home'); // views/home.handlebars
});

// show register form 
app.get('/register', (req, res) => {
  res.render('register');
});

//create the user in database
app.post('/register', (req, res) => {
  const { username, password } = req.body;

  try {
    const stmt = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)');
    stmt.run(username, password);
    // after registering, send them to login
    res.redirect('/login');
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(400).render('register', {
        error: 'Username already taken.',
      });
    }
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// show form 
app.get('/login', (req, res) => {
  res.render('login');
});

// check credentials and post the session
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  try {
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    const success = user && user.password === password;

    // Log login attempt
    db.prepare('INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, ?)').run(username, req.ip, success ? 1 : 0);

    if (!success) {
      return res.status(401).render('login', {
        error: 'Invalid username or password.',
      });
    }

    // set session
    req.session.username = user.username;
    req.session.userId = user.id;
    res.redirect('/comments');
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

//get rid of the current session
app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// list all of the comments
app.get('/comments', (req, res) => {
  try {
    const comments = db.prepare(`
      SELECT comments.text, comments.created_at, users.username as author
      FROM comments
      JOIN users ON comments.user_id = users.id
      ORDER BY comments.created_at DESC
    `).all();
    res.render('comments', { comments });
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// show forum if logged in
app.get('/comment/new', (req, res) => {
  if (!req.session.username) {
    // not logged in, send to login
    return res.redirect('/login');
  }
  res.render('newComment');
});

// add comment in database
app.post('/comment', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }

  const { text } = req.body;

  try {
    db.prepare('INSERT INTO comments (user_id, text) VALUES (?, ?)').run(req.session.userId, text);
    res.redirect('/comments');
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// start up the server, listen for connection
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Wild West Forum running at http://159.203.136.153/:${PORT}`);
});
