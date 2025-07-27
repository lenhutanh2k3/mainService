// Ví dụ: routes/user_routes.js
import express from 'express';
import userController from '../controller/user_controller.js';
import { check_Token, check_admin } from '../middleware/auth_middleware.js';
import { validateUpdateProfile } from '../middleware/validate_middleware.js';
import { upload } from '../utils/multer.js';

const router = express.Router();

// Public routes (Auth)
router.post('/register', userController.register);
router.post('/login', userController.login);
router.post('/logout', userController.logout);
router.post('/refresh-token', userController.refreshToken);

// Forgot Password (Public)
router.post('/forgot-password/request', userController.forgotPassword);
router.post('/forgot-password/verify-otp', userController.verifyOtpForForgotPassword);
router.post('/forgot-password/reset', userController.resetPassword);

// Change Password (Requires login)
router.post('/change-password/request-otp', check_Token, userController.requestChangePasswordOtp);
router.post('/change-password/resend-otp', check_Token, userController.resendChangePasswordOtp); // Gửi lại mã OTP đổi mật khẩu
router.post('/change-password/confirm', check_Token, userController.confirmChangePassword);

// User Profile (Requires login)
router.get('/me', check_Token, userController.getMe);
router.put('/profile', check_Token, upload.single('profilePicture'), validateUpdateProfile, userController.updateProfile);

// Admin Routes (Requires admin role)
// Route để lấy danh sách roles
router.get('/roles', check_Token, check_admin, userController.getAllRoles);

// Admin: Quản lý người dùng
router.get('/', check_Token, check_admin, userController.getAllUsers); // GET all users (can include deleted)
router.post('/', check_Token, check_admin, upload.single('profilePicture'), userController.createUserByAdmin); // CREATE new user by admin
router.get('/:id', check_Token, userController.getUserById); // GET user by ID (can include deleted)
router.put('/:id', check_Token, check_admin, upload.single('profilePicture'), userController.updateUserByAdmin); // UPDATE user by ID
router.put('/soft-delete/:id', check_Token, check_admin, userController.softDeleteUser); // SOFT DELETE user
router.put('/restore/:id', check_Token, check_admin, userController.restoreUser); // RESTORE user
router.delete('/:id', check_Token, check_admin, userController.deleteUser); // HARD DELETE user (cẩn thận khi dùng)
router.put('/status/:id', check_Token, check_admin, userController.toggleUserActiveStatus); // TOGGLE user active status

export default router;