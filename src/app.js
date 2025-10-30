const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

app.use(express.json());

const JWT_SECRET = 'your-very-secret-key-for-rbac';

const mockUsers = [
  { id: 1, username: 'adminUser', password: 'admin123', role: 'Admin' },
  { id: 2, username: 'modUser', password: 'moderator123', role: 'Moderator' },
  { id: 3, username: 'basicUser', password: 'user123', role: 'User' },
];

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const user = mockUsers.find(
    (u) => u.username === username && u.password === password
  );

  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const payload = {
    user: {
      id: user.id,
      username: user.username,
      role: user.role, 
    },
  };

  jwt.sign(
    payload,
    JWT_SECRET,
    { expiresIn: '1h' },
    (err, token) => {
      if (err) throw err;
      res.json({ token });
    }
  );
});

const authMiddleware = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Token missing or malformed' });
  }
  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded.user; // The payload { id, username, role } is now on req.user
    next();
  } catch (err) {
    res.status(401).json({ message: 'Token is not valid' });
  }
};

const roleCheck = (roles) => {
  return (req, res, next) => {
    // Check if the user's role from the token is in the list of allowed roles.
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Access denied: insufficient role' });
    }
    next();
  };
};



app.get('/user-profile', authMiddleware, (req, res) => {
  res.json({
    message: `Welcome to your profile, ${req.user.username}`,
    user: req.user,
  });
});

app.get('/admin-dashboard', [authMiddleware, roleCheck(['Admin'])], (req, res) => {
  res.json({
    message: 'Welcome to the Admin Dashboard!',
    adminDetails: 'Here is some highly sensitive admin data.',
  });
});

app.get('/moderator-panel', [authMiddleware, roleCheck(['Admin', 'Moderator'])], (req, res) => {
  res.json({
    message: 'Welcome to the Content Moderation Panel.',
    tasks: ['Review pending posts', 'Handle user reports'],
  });
});


app.listen(port, () => {
  console.log(`🚀 RBAC Server running on http://localhost:${port}`);
});