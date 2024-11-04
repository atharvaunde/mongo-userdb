const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/auth')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Error connecting to MongoDB', err));

// Define User Schema and Model
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  database: String
});

const User = mongoose.model('User', userSchema);

const authenticateUser = async (req, res, next) => {
  try {
    const token = req.header('Authorization').replace('Bearer ', '');

    const decoded = jwt.verify(token, 'secretkey');
    const user = await User.findOne({ _id: decoded._id });

    if (!user) {
      throw new Error();
    }

    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    console.log(error)
    res.status(401).send({ error: 'Please authenticate.' });
  }
};

const blogSchema = new mongoose.Schema({
  title: String,
  content: String,
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
});

app.post('/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 8);

    const userDBName = `user_${username}`;
    const userDB = mongoose.createConnection(`mongodb://localhost:27017/${userDBName}`);

    const Blog = userDB.model('Blog', blogSchema);

    const user = new User({ username, password: hashedPassword, database: userDBName });
    await user.save();

    res.status(201).send('User created successfully');
  } catch (error) {
    res.status(400).send(error);
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user) {
      throw new Error('Unable to login');
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      throw new Error('Unable to login');
    }

    const token = jwt.sign({ _id: user._id, database: user.database }, 'secretkey');
    res.send({ token });
  } catch (error) {
    res.status(400).send(error.message);
  }
});

// Create Blog endpoint
app.post('/blogs', authenticateUser, async (req, res) => {
  try {
    const { title, content } = req.body;
    // const userDB = mongoose.createConnection(`mongodb://localhost:27017/${req.user.database}`);
    const userDB = mongoose.connection.useDb(req.user.database);
    const Blog = userDB.model('Blog', blogSchema);
    const blog = new Blog({ title, content, author: req.user._id });
    await blog.save();
    res.status(201).send(blog);
  } catch (error) {
    res.status(400).send(error);
  }
});

app.get('/blogs', authenticateUser, async (req, res) => {
  try {
    const userDB = mongoose.connection.useDb(req.user.database);
    const Blog = userDB.model('Blog', blogSchema);
    const blogs = await Blog.find({ author: req.user._id });
    res.send(blogs);
  } catch (error) {
    res.status(500).send(error);
  }
});

const port = process.env.PORT || 3090;
app.listen(port, () => console.log(`Server is up on port ${port}`));
