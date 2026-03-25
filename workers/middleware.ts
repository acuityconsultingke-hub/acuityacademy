import cors from 'cors';
import jwt from 'jsonwebtoken';
import express from 'express';
import rateLimit from 'express-rate-limit';

const app = express();

// CORS middleware
export const corsHandler = (allowedOrigins) => {
    return cors({
        origin: (origin, callback) => {
            if (!origin || allowedOrigins.indexOf(origin) !== -1) {
                callback(null, true);
            } else {
                callback(new Error('Not allowed by CORS'));
            }
        }
    });
};

// Authentication middleware
export const authValidator = (secret) => {
    return (req, res, next) => {
        const token = req.headers['authorization']?.split(' ')[1];
        if (!token) return res.sendStatus(403);

        jwt.verify(token, secret, (err, user) => {
            if (err) return res.sendStatus(403);
            req.user = user;
            next();
        });
    };
};

// Request logger middleware
export const requestLogger = (req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
    next();
};

// Error handler middleware
export const errorHandler = (err, req, res, next) => {
    const status = err.status || 500;
    res.status(status).json({
        status,
        message: err.message || 'Internal Server Error',
    });
};

// Rate limiter middleware
export const rateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests, please try again later.',
});
