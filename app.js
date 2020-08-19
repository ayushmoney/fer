const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const nodemailer = require("nodemailer");
const rn = require("random-number");
const bcrypt = require("bcrypt");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const saltRounds=10;
const LocalStrategy = require('passport-local').Strategy;
const crypto = require("crypto");
const async = require("async");


const app = express();

//app.use(session());


let m=null;
let p=null;

app.use(bodyParser.urlencoded({ extended: true }));

const gen = rn.generator({
	min:100000,
	max:999999,
	integer:true
});
let op = gen();

app.use(session({
	secret : "you are mine",
	resave : false, 
	saveUninitialized : false,
	googleId : String
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/fermat",{useUnifiedTopology: true,useNewUrlParser : true, useCreateIndex: true});

const userSchema = new mongoose.Schema({
googleId : String
});

const addusrSchema = new mongoose.Schema({
email: String,
password: String	
});

addusrSchema.plugin(passportLocalMongoose);


userSchema.plugin(findOrCreate);

userSchema.plugin(passportLocalMongoose);// plugin is used to salt and hash, and also to store data in database 

addusrSchema.plugin(passportLocalMongoose);

const User = new mongoose.model("User_mail",userSchema);

const addUser = new mongoose.model("add_detail",addusrSchema);


passport.use(addUser.createStrategy());
//passport.use(User.createStrategy());
 //serialize function create the cookie, deserialize funtion destroy the cookie
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: '149357457651-06pkk8qqsjtqj3pjr358ll8cam3gpbr9.apps.googleusercontent.com',
    clientSecret: '165UDuiefaCty9wTHQ4YvQGW',
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
  	console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/auth/google",function(req,res){
	passport.authenticate("google", {scope: ["profile"]})(req,res);
	console.log("authenticated");
});

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    req.isAuthenticated();
    res.sendFile( __dirname+'/info.html');
  });



app.get("/register",function(req,res){
	res.sendFile(__dirname+"/register.html");
});

app.post("/register",function(req,res){
	if(req.body.password==req.body.confrmpassword){

		//creating a random numer
		
		m = req.body.username;
		p = req.body.password;
		const transporter = nodemailer.createTransport({
			service:"gmail",
			auth:{
				user:"ephermat@gmail.com",
				pass:"fermat@123"
			}
		});

		const mailOptions={
			from:"epharmat@gmail.com",
			to:req.body.username,
			subject:"OTP for fermat",
			text: `OTP : `+op 
		};

		transporter.sendMail(mailOptions,function(err,result){
			if(err){
				console.log(err);
			}else{
				console.log("Email sent: "+result.res);
			}
		});
		
		

		res.redirect("/register2");
	

	}else{
		req.flash("error","Passwords do not match.");
		res.redirect("/register");	
	}
});



//will send an OTP
app.get("/register2",function(req,res){
	res.sendFile(__dirname+"/register2.html");
	
});

app.post("/register2",function(req,res){
	console.log(op);
	console.log(req.body.OTP);
	if(req.body.OTP==op){
		//let op =gen();
		//res.sendFile(__dirname+"/info.html");
		addUser.register({username : m}, p, function(err, user){
		if(err){
			console.log(err);
		}
		else{
			res.redirect("login");
		}
	});
	}else{
		res.redirect("register2");
	}
	
});

app.get("/info",function(req,res){
	res.sendFile(__dirname+"/info.html");
})

/*app.post("/info",function(req,res){
	
    
	User.register({username : m}, p, function(err, user){
		const n = req.user._id;
		console.log(user._id);
		const a = new addUser({
				ckey:n,
	Contact: req.body.phone,
FName: req.body.FName,
LName:req.body.LName,
college:college
		})
		a.save();;
		res.redirect("/final");
	});
});*/				


	

app.get("/final",function(req,res){
	res.send(user);
});


app.get("/logout",function(req,res){
 req.logout();
 res.redirect("login")
});



app.get("/login",function(req,res){
 if(req.isAuthenticated()){
		res.sendFile( __dirname+'/info.html');
	}else{
		res.sendFile( __dirname+'/login.html');
	}
});

app.post("/login",function(req,res){
	const u = new addUser({
		username : req.body.username,
		password : req.body.password
	})
	req.login(u,function(err){
		if(err){
			console.log("not");
			res.redirect("/login");
		}else{
			passport.authenticate("local")(req,res,function(){
				res.sendFile(__dirname+"/info.html");
			});
		}
	})
});






//reset or forgot password
app.get('/forgot', function (req, res) {
    if (req.isAuthenticated()) {
        //user is alreay logged in
        return res.redirect('/');
    }

    //UI with one input for email
    res.sendFile(__dirname+"/forgot.html")
});




app.post('/forgot', function(req, res, next) {
  async.waterfall([
    function(done) {
      crypto.randomBytes(20, function(err, buf) {
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    function(token, done) {
      addUser.findOne({ email: req.body.username }, function(err, user) {
        if (!user) {
          //req.flash('error', 'No account with that email address exists.');
          return res.redirect('/forgot');
        }

        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

        user.save(function(err) {
          done(err, token, user);
        });
      });
    },
    function(token, user, done) {
      var smtpTransport = nodemailer.createTransport({
        service: 'Gmail', 
        auth: {
          user:"ephermat@gmail.com",
				pass:"fermat@123"
        }
      });
      var mailOptions = {
        to: req.body.email,	
        from: "efermat",
        subject: 'Password Reset',
        text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
          'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
          'http://' + req.headers.host + '/reset/' + token + '\n\n' +
          'If you did not request this, please ignore this email and your password will remain unchanged.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        console.log('mail sent');
        //req.flash('success', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
        done(err, 'done');
      });
    }
  ], function(err) {
    if (err) return next(err);
    res.redirect('/forgot');
  });
});



app.get('/reset/:token', function(req, res) {
  User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
    if (!user) {
      //req.flash('error', 'Password reset token is invalid or has expired.');
      console.log("not found");
      return res.redirect('/forgot');
    }
    res.render('reset', {token: req.params.token});
  });
});







app.listen(3000,function(err){
	if(err){
		console.log(err);
	}
	else{
		console.log("server started");
	}
});

