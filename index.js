import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import dbconnect from './config/db.js';
import router from './routers/index.js';
import Role from './models/role_model.js';
import User from './models/user_model.js';
import cookieParser from 'cookie-parser';
import path from 'path'; 
import { fileURLToPath } from 'url';
import { dirname } from 'path';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const PORT = process.env.PORT || 5000;
const FRONTEND_URL = process.env.FRONTEND_URL;
const app = express();


app.use(cors({
    origin: FRONTEND_URL,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());


app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

dbconnect();
router(app);

const initRole = async () => {
    try {
        const roles = ['admin', 'user'];
        for (const role of roles) {
            const exitRole = await Role.findOne({ roleName: role });
            if (!exitRole) {
                await Role.create({ roleName: role });
                console.log(`Khoi tao ${role} thanh cong`);
            }
            else {
                console.log(`${role} da ton tai`);
            }
        }
    } catch (error) {
        console.error("Loi khoi tao role");
    }
}

const createAdmin = async () => {
    try {
        const emailAdmin = "admin@gmail.com";
        const adminPass = "admin1304";
        const existingAdmin = await User.findOne({ email: emailAdmin });
        if (existingAdmin) {
            console.log(`admin da ton tai voi ${emailAdmin}`);
            return;
        }
        const adminRole = await Role.findOne({ roleName: 'admin' });
        if (!adminRole) {
            console.error('role admin');
            return;
        }
        const newAdmin = new User({
            // username: adminUsername, // Backend user_model.js không có trường username cho register/login
            email: emailAdmin,
            password: adminPass,
            role: adminRole._id,
            isActive: true
        });
        await newAdmin.save();
        console.log('Admin user created successfully:');
    } catch (error) {
        console.error('Error creating admin user:', error);
    }
}

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    initRole();
    createAdmin();
});