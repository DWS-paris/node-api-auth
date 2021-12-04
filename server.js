/* 
Imports
*/
    // NPM modules
    require('dotenv').config(); //=> https://www.npmjs.com/package/dotenv
    const express = require('express'); //=> https://www.npmjs.com/package/express
    const bcrypt = require('bcryptjs'); //=> https://www.npmjs.com/package/bcryptjs
    const passport = require('passport'); //=> https://www.npmjs.com/package/passport
    const cookieParser = require('cookie-parser'); //=> https://www.npmjs.com/package/cookie-parser

    // Services
    const MONGOclass = require('./services/mongo.class');

    // Inner module
    const Model = require('./models/identity.model')
//

/* 
Server class
*/
class ServerClass{
    constructor(){
        this.server = express();
        this.port = process.env.PORT;
        this.MongoDB = new MONGOclass();
        this.passport = passport;
    }

    init(){
        //=> Set body request with ExpressJS (http://expressjs.com/fr/api.html#express.json)
        this.server.use(express.json({limit: '20mb'}));
        this.server.use(express.urlencoded({ extended: true }))

        //=> Set CookieParser to setup serverside cookies
        this.server.use(cookieParser(process.env.COOKIE_SECRET));

        // Set authentication
        this.server.use(passport.initialize());

        const { setAutentication } = require('./services/auth.service');
        setAutentication(passport);

        //=> Start server setup
        this.setup();
    }

    setup(){
        /* 
        AUTH: Register user
        */
            this.server.post('/register', async (req, res) => {
                // Check request body
                if( typeof req.body === 'undefined' || req.body === null || Object.keys(req.body).length === 0 ){ 
                    // Send body error
                    return res.status(500).json({
                        endpoint: req.originalUrl,
                        method: req.method,
                        message: `No data provided in the body request`,
                        err: null,
                        data: null,
                        status: 500
                    });
                }
                else{
                    // Check mandatory informations
                    if( !req.body.email || !req.body.password ){
                        // Send mandatory error
                        return res.status(500).json({
                            endpoint: req.originalUrl,
                            method: req.method,
                            message: `Miss mandatory informations email or password`,
                            err: null,
                            data: null,
                            status: 500
                        });
                    }
                    else{
                        // Register new user
                        Model.create({
                            email: req.body.email,
                            password: await bcrypt.hash( req.body.password, 10 )
                        })
                        .then( mongooseSuccess => {
                            // Send success request
                            return res.status(200).json({
                                endpoint: req.originalUrl,
                                method: req.method,
                                message: `Request succeed`,
                                err: null,
                                data: mongooseSuccess,
                                status: 200
                            });
                        })
                        .catch( mongooseError => {
                            // Send error request
                            return res.status(500).json({
                                endpoint: req.originalUrl,
                                method: req.method,
                                message: `Request failed`,
                                err: mongooseError,
                                data: null,
                                status: 500
                            });
                        })
                    }
                }
            });
        //

        /* 
        AUTH: Log user
        */
            this.server.post('/login', (req, res) => {
                // Check request body
                if( typeof req.body === 'undefined' || req.body === null || Object.keys(req.body).length === 0 ){ 
                    // Send body error
                    return res.status(500).json({
                        endpoint: req.originalUrl,
                        method: req.method,
                        message: `No data provided in the body request`,
                        err: null,
                        data: null,
                        status: 500
                    });
                }
                else{
                    // Check mandatory informations
                    if( !req.body.email || !req.body.password ){
                        // Send mandatory error
                        return res.status(500).json({
                            endpoint: req.originalUrl,
                            method: req.method,
                            message: `Miss mandatory informations email or password`,
                            err: null,
                            data: null,
                            status: 500
                        });
                    }
                    else{
                        // Get identity from email
                        Model.findOne({
                            email: req.body.email
                        })
                        .exec( ( mongooseError, mongooseSuccess ) => {
                            if( mongooseError ){ 
                                // Send error request
                                return res.status(500).json({
                                    endpoint: req.originalUrl,
                                    method: req.method,
                                    message: `Request failed`,
                                    err: mongooseError,
                                    data: null,
                                    status: 500
                                });
                            }
                            else{ 
                                // Check if identity is found
                                if(mongooseSuccess === null){
                                    // Send error request
                                    return res.status(500).json({
                                        endpoint: req.originalUrl,
                                        method: req.method,
                                        message: `Email not found`,
                                        err: null,
                                        data: null,
                                        status: 500
                                    });
                                }
                                else{
                                    // Check identity password
                                    const validatedPassword = bcrypt.compareSync( req.body.password, mongooseSuccess.password );
                                    if( !validatedPassword ){ 
                                        // Send error password
                                        return res.status(500).json({
                                            endpoint: req.originalUrl,
                                            method: req.method,
                                            message: `Password mismatch`,
                                            err: null,
                                            data: null,
                                            status: 500
                                        });
                                    }
                                    else{
                                        // Generate identity JWT
                                        const javascriptWebToken = mongooseSuccess.generateJwt(mongooseSuccess);
                                        res.cookie( process.env.COOKIE_NAME, javascriptWebToken, { maxAge: 700000, httpOnly: true } );

                                        // Send success request
                                        return res.status(200).json({
                                            endpoint: req.originalUrl,
                                            method: req.method,
                                            message: `Request succeed`,
                                            err: null,
                                            data: { user: mongooseSuccess, token: javascriptWebToken},
                                            status: 200
                                        });
                                    }
                                }
                            }
                        })
                    }
                }
            });
        //

        /* 
        AUTH: Logout user
        */
            this.server.post('/logout', (req, res) => {
                // Check if identity is logged
                if( req.cookies[process.env.COOKIE_NAME] === undefined ){
                    // Send error password
                    return res.status(500).json({
                        endpoint: req.originalUrl,
                        method: req.method,
                        message: `Identity not logged`,
                        err: null,
                        data: null,
                        status: 500
                    });
                }
                else{
                    // Clear user credenyials
                    res.clearCookie( process.env.COOKIE_NAME )
    
                    // Send success request
                    return res.status(200).json({
                        endpoint: req.originalUrl,
                        method: req.method,
                        message: `Request succeed`,
                        err: null,
                        data: null,
                        status: 200
                    });
                }
            });
        //


        /* 
        AUTH: Protected route
        */
            this.server.post('/protected', passport.authenticate('jwt', { session: false }), (req, res) => {
                // Send success request
                return res.status(200).json({
                    endpoint: req.originalUrl,
                    method: req.method,
                    message: `Request succeed`,
                    err: null,
                    data: req.user,
                    status: 200
                });
            });
        //
    //

        //=> Launch server
        this.launch();
    }

    launch(){
        // Start MongoDB connection
        this.MongoDB.connectDb()
        .then( db => {
            // Start server
            this.server.listen(this.port, () => {
                console.log({
                    node: `http://localhost:${this.port}`,
                    mongo: db.url,
                });
            });
        })
        .catch( dbErr => console.log('MongoDB Error', dbErr));
    }
}
//

/* 
Start server
*/
    const apIRestfull = new ServerClass();
    apIRestfull.init();
//