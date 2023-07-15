const userModel = require("../models/user");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const SECRET_KEY = process.env.SECRET_KEY;

const signup = async (req, res) => {   

    const { username, email, password } = req.body;
    try {
        // existing user check
        const existingUser = await userModel.findOne({ email: email });
        if (existingUser) {
            return res.status(400).json({ message: "user already exists" });
        }

        // hashed password
        const hashedPassword = await bcrypt.hash(password, 10);

        //user create
        const result = await userModel.create({
            email: email,
            password: hashedPassword,
            username: username
        });

        // token generate
        const token = jwt.sign({email: result.email, id: result._id}, SECRET_KEY);
        res.status(200).json({user: result, token: token});

    } catch (error) {
        console.log(error);
        res.status(5000).json({message: "Something went wrong"});
    }  
}

const signin = async (req, res) => {

    const {email, password} = req.body;
    try {
        // existing user check
        const existingUser = await userModel.findOne({ email: email });
        if (!existingUser) {
            return res.status(404).json({ message: "user not found" });
        }

        // password match
        const matchPassword = await bcrypt.compare(password, existingUser.password);
        
        if(!matchPassword){
            return res.status(400).json({message: "Invalid Credentials"});
        }

        // token generate
        const token = jwt.sign({email: existingUser.email, id: existingUser._id}, SECRET_KEY);
        res.status(201).json({user: existingUser, token: token});


    } catch (error) {
        console.log(error);
        res.status(5000).json({message: "Something went wrong"});
    }
}


module.exports = { signup, signin };