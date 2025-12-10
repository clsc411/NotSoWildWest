
const express = require('express');
const path = require('path');
const session = require('express-session');
const exphbs = require('express-handlebars');

const app = express();
const PORT = process.env.PORT || 3000; // fix port issue 

//'database' 
const users = [];
const comments = [];

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

//create the user in memory
app.post('/register', (req, res) => {
  const { username, password } = req.body;

  // check duplicate
  const exists = users.find((u) => u.username === username);
  if (exists) {
    return res.status(400).render('register', {
      error: 'Username already taken.',
    });
  }

  users.push({ username, password });
  // after registering, send them to login
  res.redirect('/login');
});

// show form 
app.get('/login', (req, res) => {
  res.render('login');
});

// check credentials and post the session
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!user) {
    return res.status(401).render('login', {
      error: 'Invalid username or password.',
    });
  }

  // set session
  req.session.username = username;
  res.redirect('/comments');
});

//get rid of the current session
app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// list all of the comments
app.get('/comments', (req, res) => {
  res.render('comments', { comments });
});

// show forum if logged in
app.get('/comment/new', (req, res) => {
  if (!req.session.username) {
    // not logged in, send to login
    return res.redirect('/login');
  }
  res.render('newComment');
});

// add comment in memory array 
app.post('/comment', (req, res) => {
  if (!req.session.username) {
    return res.redirect('/login');
  }

  const { text } = req.body;

  comments.push({
    author: req.session.username,
    text,
    createdAt: new Date(),
  });

  res.redirect('/comments');
});

// start up the server, listen for connection
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Wild West Forum running at http://159.203.136.153/:${PORT}`);
});
