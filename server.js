
require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const session = require('express-session');
const exphbs = require('express-handlebars');
const db = require('./db');
const { validatePassword, hashPassword, comparePassword } = require('./modules/password-utils');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 4111; // fix port issue

// trust proxy for nginx
app.set('trust proxy', true);

// middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const sessionMiddleware = session({
  secret: 'this-is-intentionally-insecure',
  resave: false,
  saveUninitialized: true,
});

app.use(sessionMiddleware);
io.engine.use(sessionMiddleware);

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

// make user available to views
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

// create user in database
app.post('/register', async (req, res) => {
  const { username, email, displayName, password, secretQuestion, secretAnswer } = req.body;

  // validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).render('register', {
      error: 'Invalid email format.',
      username,
      email,
      displayName
    });
  }

  // validate display name
  if (displayName === username) {
    return res.status(400).render('register', {
      error: 'Display name must be different from username.',
      username,
      email,
      displayName
    });
  }

  // validate password strength
  const passwordCheck = validatePassword(password);
  if (!passwordCheck.valid) {
    return res.status(400).render('register', {
      error: passwordCheck.errors.join(' '),
      username,
      email,
      displayName
    });
  }

  // validate secret question/answer
  if (!secretQuestion || !secretAnswer) {
    return res.status(400).render('register', {
      error: 'Security question and answer are required.',
      username,
      email,
      displayName
    });
  }

  try {
    const hashedPassword = await hashPassword(password);
    const hashedSecretAnswer = await hashPassword(secretAnswer.trim().toLowerCase()); // Normalize and hash answer

    const stmt = db.prepare('INSERT INTO users (username, email, display_name, password, secret_question, secret_answer) VALUES (?, ?, ?, ?, ?, ?)');
    stmt.run(username, email, displayName, hashedPassword, secretQuestion, hashedSecretAnswer);
    // redirect to login after register
    res.redirect('/login');
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      // check error field
      if (err.message.includes('users.username')) {
        return res.status(400).render('register', { error: 'Username already taken.', username, email, displayName });
      } else if (err.message.includes('users.email')) {
        return res.status(400).render('register', { error: 'Email already registered.', username, email, displayName });
      }
      return res.status(400).render('register', {
        error: 'Username or Email already taken.',
        username,
        email,
        displayName
      });
    }
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// show login form
app.get('/login', (req, res) => {
  res.render('login');
});

// check credentials and create session
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    
    // check if account locked
    if (user && user.lockout_until) {
      const lockoutTime = new Date(user.lockout_until);
      if (lockoutTime > new Date()) {
        console.log(`[LOGIN] Blocked attempt for locked user: ${username}`);
        // log blocked attempt
        db.prepare('INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, ?)').run(username, req.ip, 0);
        return res.status(403).render('login', {
          error: 'Account is temporarily locked. Please try again later.',
          username
        });
      }
    }

    let success = false;
    if (user) {
      success = await comparePassword(password, user.password);
    }

    // log login attempt
    db.prepare('INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, ?)').run(username, req.ip, success ? 1 : 0);

    if (success) {
      // reset failed attempts
      db.prepare('UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE id = ?').run(user.id);

      // set session
      req.session.username = user.username;
      req.session.userId = user.id;
      res.redirect('/comments');
    } else {
      // handle failed login
      if (user) {
        const newFailedAttempts = (user.failed_login_attempts || 0) + 1;
        let lockoutUntil = user.lockout_until;

        // lockout after 5 failed attempts
        if (newFailedAttempts >= 5) {
          lockoutUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();
          console.log(`[LOGIN] Locking out user ${username} until ${lockoutUntil}`);
        }

        db.prepare('UPDATE users SET failed_login_attempts = ?, lockout_until = ? WHERE id = ?')
          .run(newFailedAttempts, lockoutUntil, user.id);
      }

      return res.status(401).render('login', {
        username,
        error: 'Invalid username or password.',
      });
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// destroy session
app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// list all comments
app.get('/comments', (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = 20;
    const offset = (page - 1) * limit;

    // get total count
    const countResult = db.prepare('SELECT COUNT(*) as count FROM comments').get();
    const totalComments = countResult.count;
    const totalPages = Math.ceil(totalComments / limit);

    // get paginated comments
    const comments = db.prepare(`
      SELECT comments.text, comments.created_at, users.display_name as author, users.username as authorUsername, users.profile_customization
      FROM comments
      JOIN users ON comments.user_id = users.id
      ORDER BY comments.created_at DESC
      LIMIT ? OFFSET ?
    `).all(limit, offset);

    // parse profile customization
    const commentsWithProfile = comments.map(c => {
      let profile = {};
      try {
        profile = JSON.parse(c.profile_customization || '{}');
      } catch (e) {
        // ignore parse error
      }
      return {
        ...c,
        authorUsername: c.authorUsername,
        authorColor: profile.color || '#000000',
        authorAvatar: profile.avatar || '🤠',
        authorBio: profile.bio || ''
      };
    });

    res.render('comments', {
      comments: commentsWithProfile,
      currentPage: page,
      totalPages: totalPages,
      totalComments: totalComments,
      hasPrev: page > 1,
      hasNext: page < totalPages,
      prevPage: page - 1,
      nextPage: page + 1,
      showPagination: totalPages > 1
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});


// show forum if logged in
app.get('/comment/new', (req, res) => {
  if (!req.session.username) {
    // redirect if not logged in
    return res.redirect('/login');
  }
  res.render('newComment');
});

// user profile route
app.get('/user/:username', (req, res) => {
  const { username } = req.params;
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = 20;
  const offset = (page - 1) * limit;

  try {
    // get user details
    const user = db.prepare('SELECT id, display_name, username, profile_customization FROM users WHERE username = ?').get(username);

    if (!user) {
      return res.status(404).send('User not found');
    }

    let profile = {};
    try {
      profile = JSON.parse(user.profile_customization || '{}');
    } catch (e) {}

    // get total comments count for user
    const countResult = db.prepare('SELECT COUNT(*) as count FROM comments WHERE user_id = ?').get(user.id);
    const totalComments = countResult.count;
    const totalPages = Math.ceil(totalComments / limit);

    // get paginated comments for user
    const comments = db.prepare(`
      SELECT text, created_at
      FROM comments
      WHERE user_id = ?
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `).all(user.id, limit, offset);

    res.render('userProfile', {
      profileDisplayName: user.display_name,
      profileUsername: user.username,
      profileColor: profile.color || '#000000',
      profileAvatar: profile.avatar || '🤠',
      profileBio: profile.bio || '',
      comments: comments,
      currentPage: page,
      totalPages: totalPages,
      totalComments: totalComments,
      hasPrev: page > 1,
      hasNext: page < totalPages,
      prevPage: page - 1,
      nextPage: page + 1,
      showPagination: totalPages > 1
    });

  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// add comment to database
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

// show profile form
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
    // verify password first
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

    // validate email format
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

    // validate display name
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

    // validate display name length
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

    // validate customization
    // validate color hex
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

    // validate bio length
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
    
    // update session
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

  if (!currentPassword || !newPassword) {
    return res.status(400).render('changePassword', {
      error: 'All fields are required.',
    });
  }

  try {
    // get current user
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);

    if (!user) {
      console.error(`[CHANGE-PASSWORD] User not found for ID: ${req.session.userId}`);
      return res.status(404).send('User not found');
    }

    // verify current password
    const validCurrent = await comparePassword(currentPassword, user.password);
    if (!validCurrent) {
      return res.status(400).render('changePassword', {
        error: 'Incorrect current password.',
      });
    }

    // validate new password strength
    const passwordCheck = validatePassword(newPassword);
    if (!passwordCheck.valid) {
      return res.status(400).render('changePassword', {
        error: passwordCheck.errors.join(' '),
      });
    }

    // hash and update password
    const hashedNewPassword = await hashPassword(newPassword);
    db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashedNewPassword, req.session.userId);

    // invalidate session
    req.session.destroy(() => {
      res.redirect('/login');
    });

  } catch (err) {
    console.error('[CHANGE-PASSWORD ERROR]', err);
    res.status(500).send('Internal Server Error');
  }
});

// show forgot password form
app.get('/forgot-password', (req, res) => {
  res.render('forgotPassword');
});

// handle forgot password
app.post('/forgot-password', async (req, res) => {
  const { username } = req.body;

  try {
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

    if (!user) {
      return res.render('forgotPassword', {
        error: 'User not found.'
      });
    }

    if (!user.secret_question || !user.secret_answer) {
      return res.render('forgotPassword', {
        error: 'This account does not have a security question set up. Please contact support.'
      });
    }

    res.render('securityQuestion', {
      username: user.username,
      question: user.secret_question
    });

  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// verify security question
app.post('/verify-security-question', async (req, res) => {
  const { username, answer } = req.body;

  try {
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

    if (!user) {
      return res.redirect('/forgot-password');
    }

    // verify answer
    const validAnswer = await comparePassword(answer.trim().toLowerCase(), user.secret_answer);
    
    if (!validAnswer) {
      return res.render('securityQuestion', {
        username: user.username,
        question: user.secret_question,
        error: 'Incorrect answer.'
      });
    }

    // generate token
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 3600000).toISOString(); // 1 hour from now

    // save token to db
    db.prepare('UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?')
      .run(token, expires, user.id);

    // redirect to reset password page
    res.redirect(`/reset-password/${token}`);

  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// show reset password form
app.get('/reset-password/:token', (req, res) => {
  const { token } = req.params;

  try {
    const user = db.prepare('SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > ?')
      .get(token, new Date().toISOString());

    if (!user) {
      return res.render('forgotPassword', {
        error: 'Password reset token is invalid or has expired.'
      });
    }

    res.render('resetPassword', { token });
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// handle reset password
app.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    const user = db.prepare('SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > ?')
      .get(token, new Date().toISOString());

    if (!user) {
      return res.render('forgotPassword', {
        error: 'Password reset token is invalid or has expired.'
      });
    }

    // validate new password strength
    const passwordCheck = validatePassword(password);
    if (!passwordCheck.valid) {
      return res.render('resetPassword', {
        token,
        error: passwordCheck.errors.join(' ')
      });
    }

    // hash new password
    const hashedPassword = await hashPassword(password);

    // update password and clear token
    db.prepare('UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?')
      .run(hashedNewPassword, user.id);

    res.render('login', {
      success: 'Password has been reset successfully. Please login.'
    });

  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// start server
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Wild West Forum running at http://159.203.136.153/:${PORT}`);
});

// chat route
app.get('/chat', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  res.render('chat');
});

// api get chat history
app.get('/api/chat/history', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const messages = db.prepare(`
      SELECT chat_messages.text, chat_messages.created_at as timestamp, users.display_name as user, users.profile_customization
      FROM chat_messages
      JOIN users ON chat_messages.user_id = users.id
      ORDER BY chat_messages.created_at ASC
      LIMIT 50
    `).all();

    const formattedMessages = messages.map(m => {
      let profile = {};
      try {
        profile = JSON.parse(m.profile_customization || '{}');
      } catch (e) {}
      return {
        user: m.user,
        text: m.text,
        timestamp: m.timestamp,
        color: profile.color || '#000000',
        avatar: profile.avatar || '🤠'
      };
    });

    res.json(formattedMessages);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// api send message
app.post('/api/chat/message', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { message } = req.body;
  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  try {
    // save to db
    db.prepare('INSERT INTO chat_messages (user_id, text) VALUES (?, ?)').run(req.session.userId, message);

    // fetch user details
    const user = db.prepare('SELECT display_name, profile_customization FROM users WHERE id = ?').get(req.session.userId);
    let profile = {};
    try {
      profile = JSON.parse(user.profile_customization || '{}');
    } catch (e) {}

    const msgData = {
      user: user.display_name,
      text: message,
      timestamp: new Date(),
      color: profile.color || '#000000',
      avatar: profile.avatar || '🤠'
    };

    // broadcast via socket
    io.emit('chat message', msgData);

    res.json({ success: true, message: msgData });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// socket logic
io.on('connection', (socket) => {
  const session = socket.request.session;
  
  if (session && session.userId) {
    console.log(`User connected: ${session.username}`);
    
    socket.on('chat message', (msg) => {
      // fetch latest customization
      try {
        // save to db
        db.prepare('INSERT INTO chat_messages (user_id, text) VALUES (?, ?)').run(session.userId, msg);

        const user = db.prepare('SELECT display_name, profile_customization FROM users WHERE id = ?').get(session.userId);
        let profile = {};
        try {
          profile = JSON.parse(user.profile_customization || '{}');
        } catch (e) {}

        io.emit('chat message', {
          user: user.display_name,
          text: msg,
          timestamp: new Date(),
          color: profile.color || '#000000',
          avatar: profile.avatar || '🤠'
        });
      } catch (err) {
        console.error('Error fetching user for chat:', err);
      }
    });

    socket.on('disconnect', () => {
      console.log(`User disconnected: ${session.username}`);
    });
  } else {
    console.log('Unauthenticated user connected to socket');
    socket.disconnect();
  }
});
