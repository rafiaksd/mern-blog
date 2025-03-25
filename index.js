const express = require('express')
const cors = require('cors')
const app = express()

const corsOptions = {
  origin: 'https://rafiaksd.github.io', // The GitHub Pages URL
  methods: ['GET', 'POST', 'PUT', 'DELETE'], // Allowed methods
  allowedHeaders: ['Content-Type', 'Authorization'], // Allow specific headers
  credentials: true, // Allow cookies to be sent with requests
};

app.use(cors(corsOptions)); // Apply CORS middleware first

const mongoose = require('mongoose')
const User = require('./models/user.js')
const Post = require('./models/post.js')

const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')

require('dotenv').config();

const salt = bcrypt.genSaltSync(10)
const mongoURI = process.env.MONGO_CONNECT_URI;
const jwtSecret = process.env.JWT_SECRET

const PORT = process.env.PORT

app.use(express.json())
app.use(cookieParser())

mongoose.connect(mongoURI)

app.post('/register', async (req, res)=>{
     const {username, password} = req.body;
     try{
          const userDoc = await User.create({username: username, password: bcrypt.hashSync(password, salt),})
          res.json(userDoc)
     } catch (e){
          console.log('exception: ', e)
          res.status(400).json(e)
     }
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const userDoc = await User.findOne({ username });

  if (!userDoc || !bcrypt.compareSync(password, userDoc.password)) {
    return res.status(400).json('Incorrect credentials');
  }

  jwt.sign({ username, id: userDoc._id }, jwtSecret, {}, (err, token) => {
    if (err) throw err;
    res.cookie('token', token, { httpOnly: true }).json({
      id: userDoc._id,
      username,
      token // Include the token in the response
    });
  });
});

   

app.get('/profile', (req, res)=>{
     const {token} = req.cookies
     jwt.verify(token, jwtSecret, {}, (err, info)=>{
          if (err) throw err;
          res.json(info)
     })
})

app.post('/logout', (req, res)=>{
     res.cookie('token', '').json('logoutted')
})


app.post('/post', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1]; // Extract token from 'Authorization: Bearer <token>'

  if (!token) {
    return res.status(401).json({ message: 'Token is required!!!' });
  }

  jwt.verify(token, jwtSecret, {}, async (err, info) => {
    if (err) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    const { title, summary, content } = req.body;

    const postDoc = await Post.create({
      title: title,
      summary: summary,
      content: content,
      author: info.id,
    });

    res.json(postDoc);
  });
});


app.put('/post', async (req, res) => {
   
     const { token } = req.cookies;
     jwt.verify(token, jwtSecret, {}, async (err, info) => {
       if (err) throw err;
   
       const { id, title, summary, content } = req.body;
       const postDoc = await Post.findById(id);
   
       // Check if the logged-in user is the author of the post
       const isAuthor = JSON.stringify(postDoc.author) === JSON.stringify(info.id);
   
       if (!isAuthor) {
         return res.status(400).json('You are not the author!');
       }
   
       // Update postDoc with the new data
       postDoc.title = title || postDoc.title;
       postDoc.summary = summary || postDoc.summary;
       postDoc.content = content || postDoc.content;
   
       // Save the updated post
       await postDoc.save();
   
       res.json(postDoc);  // Send back the updated post
     });
});
   

app.get('/post', async (req, res)=> {
     const posts = await Post.find().populate('author', ['username']).sort({createdAt : -1}).limit(20)
     res.json(posts)
})

app.get('/post/:id', async(req, res)=>{
     const {id} = req.params
     const postDoc = await Post.findById(id).populate('author', ['username'])
     res.json(postDoc)
})

app.listen(PORT)
