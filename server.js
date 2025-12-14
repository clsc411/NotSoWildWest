
const express = require('express');
const path = require('path');
const session = require('express-session');
const exphbs = require('express-handlebars');
const db = require('./db');
const { validatePassword, hashPassword, comparePassword } = require('./modules/password-utils');

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
    helpers: {
      eq: (a, b) => a === b
    }
  })
);
app.set('view engine', 'handlebars');
app.set('views', path.join(__dirname, 'views'));

// make the user available to ALL views
app.use((req, res, next) => {
  res.locals.currentUser = req.session.displayName || req.session.username || null;
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
app.post('/register', async (req, res) => {
  const { username, email, displayName, password } = req.body;

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).render('register', {
      error: 'Invalid email format.',
    });
  }

  // Validate display name != username
  if (displayName === username) {
    return res.status(400).render('register', {
      error: 'Display name must be different from username.',
    });
  }

  // Validate password strength
  const passwordCheck = validatePassword(password);
  if (!passwordCheck.valid) {
    return res.status(400).render('register', {
      error: passwordCheck.errors.join(' '),
    });
  }

  try {
    const hashedPassword = await hashPassword(password);
    const stmt = db.prepare('INSERT INTO users (username, email, display_name, password) VALUES (?, ?, ?, ?)');
    stmt.run(username, email, displayName, hashedPassword);
    // after registering, send them to login
    res.redirect('/login');
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      // Check which field caused the error
      if (err.message.includes('users.username')) {
        return res.status(400).render('register', { error: 'Username already taken.' });
      } else if (err.message.includes('users.email')) {
        return res.status(400).render('register', { error: 'Email already registered.' });
      }
      return res.status(400).render('register', {
        error: 'Username or Email already taken.',
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
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    
    // Check if account is locked
    if (user && user.lockout_until && new Date(user.lockout_until) > new Date()) {
      // Log blocked attempt
      db.prepare('INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, ?)').run(username, req.ip, 0);
      return res.status(403).render('login', {
        error: 'Account is temporarily locked. Please try again later.',
      });
    }

    let success = false;
    if (user) {
      success = await comparePassword(password, user.password);
    }

    // Log login attempt
    db.prepare('INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, ?)').run(username, req.ip, success ? 1 : 0);

    if (success) {
      // Reset failed attempts on successful login
      db.prepare('UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE id = ?').run(user.id);

      // set session
      req.session.username = user.username;
      req.session.userId = user.id;
      res.redirect('/comments');
    } else {
      // Handle failed login
      if (user) {
        const newFailedAttempts = (user.failed_login_attempts || 0) + 1;
        let lockoutUntil = user.lockout_until;

        // Lockout logic: 5 failed attempts locks for 15 minutes
        if (newFailedAttempts >= 5) {
          lockoutUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();
        }

        db.prepare('UPDATE users SET failed_login_attempts = ?, lockout_until = ? WHERE id = ?')
          .run(newFailedAttempts, lockoutUntil, user.id);
      }

      return res.status(401).render('login', {
        error: 'Invalid username or password.',
      });
    }
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
    const comments = db.prepare(`display_
      SELECT comments.text, comments.created_at, users.display_name as author, users.profile_customization
      FROM comments
      JOIN users ON comments.user_id = users.id
      ORDER BY comments.created_at DESC
    `).all();

    // Parse profile customization for each comment
    const commentsWithProfile = comments.map(c => {
      let profile = {};
      try {
        profile = JSON.parse(c.profile_customization || '{}');
      } catch (e) {
        // ignore parse error
      }
      return {
        ...c,
        authorColor: profile.color || '#000000',
        authorAvatar: profile.avatar || '🤠',
        authorBio: profile.bio || ''
      };
    });

    res.render('comments', { comments: commentsWithProfile });
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

// profile form
app.get('/profile', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  
  try {
    const user = db.prepare('SELECT display_name, email, profile_customization FROM users WHERE id = ?').get(req.session.userId);
    
    let profile = {};
    try {
      profile = JSON.parse(user.profile_customization || '{}');
    } catch (e) {}

    res.render('profile', {
      currentUserDisplayName: user.display_name,
      currentUserEmail: user.email,
      profileColor: profile.color || '#000000',
      profileAvatar: profile.avatar || '🤠',
      profileBio: profile.bio || ''
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// handle profile update
app.post('/profile', async (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }

  const { displayName, email, password, color, avatar, bio } = req.body;
  const username = req.session.username; // Get username from session for validation

  try {
    // Verify password first
    const user = db.prepare('SELECT password FROM users WHERE id = ?').get(req.session.userId);
    const validPassword = await comparePassword(password, user.password);
    
    if (!validPassword) {
      return res.status(400).render('profile', {
        error: 'Incorrect password. Changes not saved.',
        currentUserDisplayName: displayName,
        currentUserEmail: email,
        profileColor: color,
        profileAvatar: avatar,
        profileBio: bio
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).render('profile', {
        error: 'Invalid email format.',
        currentUserDisplayName: displayName,
        currentUserEmail: email,
        profileColor: color,
        profileAvatar: avatar,
        profileBio: bio
      });
    }

    // Validate display name != username
    if (displayName === username) {
      return res.status(400).render('profile', {
        error: 'Display name must be different from username.',
        currentUserDisplayName: displayName,
        currentUserEmail: email,
        profileColor: color,
        profileAvatar: avatar,
        profileBio: bio
      });
    }

    // Validate display name length and characters
    if (displayName.length < 3 || displayName.length > 30) {
      return res.status(400).render('profile', {
        error: 'Display name must be between 3 and 30 characters.',
        currentUserDisplayName: displayName,
        currentUserEmail: email,
        profileColor: color,
        profileAvatar: avatar,
        profileBio: bio
      });
    }
    if (!/^[a-zA-Z0-9_ ]+$/.test(displayName)) {
      return res.status(400).render('profile', {
        error: 'Display name can only contain letters, numbers, spaces, and underscores.',
        currentUserDisplayName: displayName,
        currentUserEmail: email,
        profileColor: color,
        profileAvatar: avatar,
        profileBio: bio
      });
    }

    // Validate customization
    // Color: simple hex check
    if (color && !/^#[0-9A-F]{6}$/i.test(color)) {
       return res.status(400).render('profile', {
        error: 'Invalid color format.',
        currentUserDisplayName: displayName,
        currentUserEmail: email,
        profileColor: color,
        profileAvatar: avatar,
        profileBio: bio
      });
    }

    // Bio: length check
    if (bio && bio.length > 200) {
       return res.status(400).render('profile', {
        error: 'Bio must be under 200 characters.',
        currentUserDisplayName: displayName,
        currentUserEmail: email,
        profileColor: color,
        profileAvatar: avatar,
        profileBio: bio
      });
    }

    const customization = JSON.stringify({
      color: color || '#000000',
      avatar: avatar || '🤠',
      bio: bio || ''
    });

    db.prepare('UPDATE users SET display_name = ?, email = ?, profile_customization = ? WHERE id = ?')
      .run(displayName, email, customization, req.session.userId);
    
    // Update session
    req.session.displayName = displayName;
    
    res.render('profile', {
      success: 'Profile updated successfully.',
      currentUserDisplayName: displayName,
      currentUserEmail: email,
      profileColor: color,
      profileAvatar: avatar,
      profileBio: bio
    });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
       return res.status(400).render('profile', {
        error: 'Email already registered.',
        currentUserDisplayName: displayName,
        currentUserEmail: email,
        profileColor: color,
        profileAvatar: avatar,
        profileBio: bio
      });
    }
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// show 
// show change password form
app.get('/change-password', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  res.render('changePassword');
});

// handle change password
app.post('/change-password', async (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }

  const { currentPassword, newPassword } = req.body;

  try {
    // Get current user
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);

    // Verify current password
    const validCurrent = await comparePassword(currentPassword, user.password);
    if (!validCurrent) {
      return res.status(400).render('changePassword', {
        error: 'Incorrect current password.',
      });
    }

    // Validate new password strength
    const passwordCheck = validatePassword(newPassword);
    if (!passwordCheck.valid) {
      return res.status(400).render('changePassword', {
        error: passwordCheck.errors.join(' '),
      });
    }

    // Hash new password and update
    const hashedNewPassword = await hashPassword(newPassword);
    db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashedNewPassword, req.session.userId);

    // Invalidate session to force re-login
    req.session.destroy(() => {
      res.redirect('/login');
    });

  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// start up the server, listen for connection
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Wild West Forum running at http://159.203.136.153/:${PORT}`);
});
