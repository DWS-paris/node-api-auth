/*
Import
*/
    const mongoose = require('mongoose');
    const { Schema } = mongoose;
    const jwt = require('jsonwebtoken');
//

/*
Definition
*/
    const MySchema = new Schema({
        email: {
            type: String,
            required: true,
            unique: true,
        },
        password: {
            type: String,
            required: true,
        },

        dateCreated: { 
            type: Date, 
            default: new Date() 
        },
    })
//

/* 
Methods
*/
    MySchema.methods.generateJwt = user => {
        // Set expiration
        const expiryToken = new Date();
        expiryToken.setDate( expiryToken.getDate() + 59 );

        // Set token
        const jwtObject = {
            _id: user._id,
            email: user.email,
            password: user.password,
            
            // Set timeout
            expireIn: '10s',
            exp: parseInt( expiryToken.getTime() / 100, 10 )
        }

        // Retunr JWT
        return jwt.sign( jwtObject, process.env.JWT_SECRET );
    }
//

/* 
Export
*/
    module.exports = mongoose.model('identity', MySchema)
//