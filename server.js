const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;

// Connect to MongoDB
mongoose.connect(process.env.DATABASE_URL, { useNewUrlParser: true, useUnifiedTopology: true });

// User model
const UserSchema = new mongoose.Schema({
  username: String,
  password: String,
});
const User = mongoose.model('User', UserSchema);

// Middleware
app.use(bodyParser.json());

const JWT_SECRET = process.env.JWT_SECRET; // Replace this with a strong secret from your .env file

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Register route
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.status(201).send('User registered');
});

// Login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '2h' });
        res.json({ token });
    } else {
        res.status(400).send('Invalid credentials');
    }
});

// Get all users
app.get('/users', authenticateToken, async (req, res) => {
    const users = await User.find({});
    res.json(users);
});

// Delete user
app.delete('/user/:username', authenticateToken, async (req, res) => {
    const { username } = req.params;
    await User.findOneAndDelete({ username });
    res.send('User deleted');
});

// Update user password
app.put('/user/:username', authenticateToken, async (req, res) => {
    const { username } = req.params;
    const { newPassword } = req.body;
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await User.findOneAndUpdate({ username }, { password: hashedPassword });
    res.send('User updated');
});

app.post('/todo', authenticateToken, async (req, res) => {
    const { content } = req.body;
    const user = await User.findOne({ username: req.user.username });
    const todo = new Todo({
      user: user._id,
      content,
      completed: false,
    });
    await todo.save();
    res.status(201).send('Todo created');
  });
  
  // Update todo
  app.put('/todo/:todoId', authenticateToken, async (req, res) => {
    const { todoId } = req.params;
    const { content, completed } = req.body;
    const user = await User.findOne({ username: req.user.username });
    const todo = await Todo.findOneAndUpdate({ _id: todoId, user: user._id }, { content, completed }, { new: true });
    if (todo) {
      res.json(todo);
    } else {
      res.status(404).send('Todo not found or not yours');
    }
  });
  
  // Delete todo
  app.delete('/todo/:todoId', authenticateToken, async (req, res) => {
    const { todoId } = req.params;
    const user = await User.findOne({ username: req.user.username });
    const result = await Todo.findOneAndDelete({ _id: todoId, user: user._id });
    if (result) {
      res.send('Todo deleted');
    } else {
      res.status(404).send('Todo not found or not yours');
    }
  });
  
  // Get all todos for a user
  app.get('/todos', authenticateToken, async (req, res) => {
    const user = await User.findOne({ username: req.user.username });
    const todos = await Todo.find({ user: user._id });
    res.json(todos);
  });
  

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
