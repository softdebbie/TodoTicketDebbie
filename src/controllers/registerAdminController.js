import nodemailer from "nodemailer";
import crypto from "crypto";
import jsonwebtoken from "jsonwebtoken";
import bcryptjs from "bcryptjs";

import adminModel from "../models/admin.js";

import {config} from "../../config.js";
import {register} from "module";


//array de funciones
const registerAdminController = {};

registerAdminController.register = async (req, res) => {
    try{
        const{
           name, 
           email, 
           password, 
           isVerified, 
           loginAttempts, 
           timeOut, 
        } = req.body;

        const existAdmin = await adminModel.findOne({email});

        if(existAdmin){
            return res.status(400).json({message: "Admin already exist"})
        }

        const passwordHashed = await bcryptjs.hash(password, 10);
        
        const randomCode = crypto.randomBytes(3).toString("hex");

        const token = jsonwebtoken.sign(
            {randomCode,
            name, 
            email, 
            password: passwordHashed, 
            isVerified, 
            loginAttempts, 
            timeOut
        }, 
        config.JWT.secret, 
        {expiresIn: "15m"},
        );

        res.cookie("registrationCookie", token, {maxAge: 15*60*1000});

        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: config.email.user_email,
                pass: config.email.user_password,
            }
        });

        const mailOptions = {
            from: config.email.user_email,
            to: email, 
            subject: "Verificacion de cuenta",
            text: 
            "Usa este codigo para verificar tu cuenta" + randomCode
            + "expira en 15 mins",
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if(error){
                console.log("error"+error);
                return res.status(500).json({message: "error sending email"});
            }
            return res.status(200).json({message: "Email sent"});
        });
    }catch(error){
        console.log("error"+error)
        return res.status(500).json({message: "Internal Server Error"});
    }
};

registerAdminController.verifyCode = async (req, res) => {
    try{
        const {verificationCodeRequest} = req.body;
        const token = req.cookies.registrationCookie;
        const decoded = jsonwebtoken.verify(token, config.JWT.secret);
        const{
            randomCode: storedCode,
            name, 
            email, 
            password, 
            isVerified,
            loginAttempts,
            timeOut,
        } = decoded;

        if(verificationCodeRequest !== storedCode) {
            return res.status(400).json({message: "Invalid Code"});
        }

        const newAdmin = adminModel({
            name, 
            email, 
            password, 
            isVerified: true,
        })
        await newAdmin.save();
        res.clearCookie("registrationCookie");
        return res.status(200).json({message: "Customer registered"});
    }catch(error){
        console.log("error"+error)
        return res.status(500).json({message: "Internal Server Error"});
    }
};

export default registerAdminController;