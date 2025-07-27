// middlewares/validation_middleware.js
import { body, validationResult } from 'express-validator';
import response from '../utils/response.js';

export const validate = (req, res, next) => {
    const errors = validationResult(req);
    if (errors.isEmpty()) {
        return next();
    }
    const extractedErrors = [];
    errors.array().map(err => extractedErrors.push({ [err.param]: err.msg }));

    return response(res, 422, 'Lỗi xác thực dữ liệu', extractedErrors);
};
export const validateRegister = [
    body('email')
        .trim()
        .notEmpty().withMessage('Email không được để trống')
        .isEmail().withMessage('Email không hợp lệ'),
    body('password')
        .notEmpty().withMessage('Mật khẩu không được để trống')
        .isLength({ min: 6 }).withMessage('Mật khẩu phải có ít nhất 6 ký tự'),
    body('repeat_password')
        .notEmpty().withMessage('Xác nhận mật khẩu không được để trống')
        .custom((value, { req }) => {
            if (value !== req.body.password) {
                throw new Error('Xác nhận mật khẩu không khớp');
            }
            return true;
        }),
    validate
];

export const validateLogin = [
    body('email')
        .trim()
        .notEmpty().withMessage('Email không được để trống')
        .isEmail().withMessage('Email không hợp lệ'),
    body('password')
        .notEmpty().withMessage('Mật khẩu không được để trống'),
    validate
];

export const validateShippingAddress = [
    body('address')
        .notEmpty().withMessage('Địa chỉ không được để trống')
        .trim(),
    body('fullName')
        .notEmpty().withMessage('Tên đầy đủ không được để trống')
        .trim(),
    body('phoneNumber')
        .notEmpty().withMessage('Số điện thoại không được để trống')
        .trim()
        .matches(/^\+?[\d\s-]{9,}$/).withMessage('Số điện thoại không hợp lệ'),
    body('ward')
        .notEmpty().withMessage('Phường/Xã không được để trống')
        .trim(),
    body('district')
        .notEmpty().withMessage('Quận/Huyện không được để trống')
        .trim(),
    body('city')
        .notEmpty().withMessage('Tỉnh/Thành phố không được để trống')
        .trim(),
    body('addressType')
        .optional()
        .isIn(['home', 'office', 'other']).withMessage('Loại địa chỉ không hợp lệ'),
    body('isDefault')
        .optional()
        .isBoolean().withMessage('Trạng thái mặc định phải là boolean'),
    validate
];

export const validateUpdateShippingAddress = [
    body('address')
        .optional()
        .trim()
        .notEmpty().withMessage('Địa chỉ không được để trống'),
    body('fullName')
        .optional()
        .trim()
        .notEmpty().withMessage('Tên đầy đủ không được để trống'),
    body('phoneNumber')
        .optional()
        .trim()
        .matches(/^\+?[\d\s-]{9,}$/).withMessage('Số điện thoại không hợp lệ'),
    body('ward')
        .optional()
        .trim()
        .notEmpty().withMessage('Phường/Xã không được để trống'),
    body('district')
        .optional()
        .trim()
        .notEmpty().withMessage('Quận/Huyện không được để trống'),
    body('city')
        .optional()
        .trim()
        .notEmpty().withMessage('Tỉnh/Thành phố không được để trống'),
    body('addressType')
        .optional()
        .isIn(['home', 'office', 'other']).withMessage('Loại địa chỉ không hợp lệ'),
    body('isDefault')
        .optional()
        .isBoolean().withMessage('Trạng thái mặc định phải là boolean'),
    validate
];
export const validateRequestChangePassword = [
    body('email')
        .trim()
        .notEmpty().withMessage('Email không được để trống')
        .isEmail().withMessage('Email không hợp lệ'),
    validate
];
export const validateChangePasswordWithOtp = [
    body('otp')
        .notEmpty().withMessage('Mã OTP không được để trống')
        .isLength({ min: 6, max: 6 }).withMessage('Mã OTP phải có 6 chữ số'),
    body('newPassword')
        .notEmpty().withMessage('Mật khẩu mới không được để trống')
        .isLength({ min: 6 }).withMessage('Mật khẩu mới phải có ít nhất 6 ký tự'),
    body('confirmNewPassword')
        .notEmpty().withMessage('Xác nhận mật khẩu mới không được để trống')
        .custom((value, { req }) => {
            if (value !== req.body.newPassword) {
                throw new Error('Xác nhận mật khẩu mới không khớp');
            }
            return true;
        }),
    validate
];
export const validateForgotPassword = [
    body('email')
        .trim()
        .notEmpty().withMessage('Email không được để trống')
        .isEmail().withMessage('Email không hợp lệ'),
    validate
];

// Validation cho API verifyOtpForPasswordChange
export const validateVerifyOtpForPasswordChange = [
    body('otp')
        .notEmpty().withMessage('Mã OTP không được để trống')
        .isLength({ min: 6, max: 6 }).withMessage('Mã OTP phải có 6 chữ số')
        .isNumeric().withMessage('Mã OTP phải là số'),
    validate
];

// Validation cho API confirmChangePassword (đã đổi tên và thêm passwordChangeToken)
export const validateConfirmChangePassword = [
    body('passwordChangeToken')
        .notEmpty().withMessage('Token đổi mật khẩu không được để trống'),
    body('currentPassword')
        .notEmpty().withMessage('Mật khẩu hiện tại không được để trống'),
    body('newPassword')
        .notEmpty().withMessage('Mật khẩu mới không được để trống')
        .isLength({ min: 6 }).withMessage('Mật khẩu mới phải có ít nhất 6 ký tự'),
    validate
];

// Validation cho cập nhật hồ sơ người dùng
export const validateUpdateProfile = [
    body('fullName')
        .optional()
        .trim()
        .notEmpty().withMessage('Họ tên không được để trống')
        .isLength({ min: 2, max: 100 }).withMessage('Họ tên phải có từ 2 đến 100 ký tự'),
    body('phoneNumber')
        .optional()
        .trim()
        .matches(/^\+?[\d\s-]{9,}$/).withMessage('Số điện thoại không hợp lệ'),
    body('username')
        .optional()
        .trim()
        .isLength({ min: 3, max: 50 }).withMessage('Tên đăng nhập phải có từ 3 đến 50 ký tự')
        .matches(/^[a-zA-Z0-9_]+$/).withMessage('Tên đăng nhập chỉ được chứa chữ cái, số và dấu gạch dưới'),
    validate
];