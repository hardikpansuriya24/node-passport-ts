
import mongoose, {ConnectOptions, Error} from 'mongoose';
import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import passport from 'passport';
import passportLocal from 'passport-local';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import User from './User'
import dotenv from 'dotenv';
import { UserInterface} from './Interfaces/UserInterface';

const LocalStrategy = passportLocal.Strategy

mongoose.set("strictQuery", false);
mongoose.connect('mongodb+srv://node-ts:nodetsexpdemo@cluster0.e8kqvbi.mongodb.net/?retryWrites=true&w=majority', {
    useNewUrlParser: true, 
    useUnifiedTopology: true 
} as ConnectOptions, (err : Error) =>{
    if (err) throw err;

    console.log("Connected");
});

// Middleware
const app = express();
app.use(express.json());
app.use(cors({ origin: "http://localhost:3000", credentials: true }))
app.use(
  session({
    secret: "secretcode",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 }
  })
);
app.use(cookieParser());
app.use(passport.initialize());
app.use(passport.session());

// Passport 
passport.use(new LocalStrategy((username: string, password: string, done) => {
    User.findOne({ username: username }, (err : Error, user: any) => {
      if (err) throw err;
      if (!user) return done(null, false);
      bcrypt.compare(password, user.password, (err, result: boolean) => {
        if (err) throw err;
        if (result === true) {
          return done(null, user);
        } else {
          return done(null, false);
        }
      });
    });
  })
);

passport.serializeUser((user: any, cb) => {
    cb(null, user._id);
});
  
passport.deserializeUser((id: string, cb) => {
    User.findOne({ _id: id }, (err : Error, user: any) => {
        const userInformation = {
            username: user.username,
            isAdmin: user.isAdmin
        };
        cb(err, userInformation);
    });
});
  
  
// Routes

app.post("/login", passport.authenticate("local"), (req : Request, res : Response) => {
    res.send("success")
});

app.get("/user", (req : Request, res : Response) => {
    res.send(req.user);
});

app.get("/logout", (req : Request, res : Response) => {
  if (req.session) {
    req.session.destroy(err => {
      if (err) {
        res.status(400).send('Unable to log out')
      } else {
        res.send("success");
      }
    });
  } else {
    res.end()
  }
});

app.post('/register', async (req : Request, res : Response) => {

    const {username, password} = req?.body;
    if(!username || !password || typeof username !== "string" || typeof password !== "string" ){
        res.send("Inproper Values");
        return;
    }

    User.findOne({username}, async(err : Error, doc: UserInterface) => {
        if (err) throw err;
        if (doc) res.send("User Already Exists");
        if(!doc){
             // usename, password
            const hashedPassword = await bcrypt.hash(password, 10);
            const newUser = new User({
                username,
                password: hashedPassword,
            });
            await newUser.save();
            res.send("success")
        }
    });
});

app.listen(4000, ()=>{
    console.log("Server Started");
})