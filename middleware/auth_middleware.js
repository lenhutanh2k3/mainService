// middlewares/auth_middleware.js
import jwt from 'jsonwebtoken';
import response from '../utils/response.js';
import User from '../models/user_model.js'; //

export const check_Token = (req, res, next) => {

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];


    if (!token) {
        console.log('No token provided');
        return response(res, 401, 'Token không được cung cấp');
    }

    jwt.verify(token, process.env.SECRET_KEY, (err, userPayload) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                return response(res, 401, 'Token đã hết hạn, vui lòng làm mới');
            }
            return response(res, 401, 'Token không hợp lệ');
        }
        req.user = userPayload;
        next();
    });
};

// Middleware kiểm tra người dùng đã xác thực (có thể là user hoặc admin)
export const check_authenticated_user = async (req, res, next) => {
    if (!req.user || !req.user.id) {
        return response(res, 401, 'Thông tin người dùng không hợp lệ trong token. Vui lòng đăng nhập lại.');
    }
    try {
        const user = await User.findById(req.user.id).populate('role');
        if (!user) {
            return response(res, 404, 'Người dùng không tồn tại.');
        }
        // Kiểm tra nếu tài khoản bị xóa mềm
        if (user.isDeleted) {
            return response(res, 403, 'Tài khoản của bạn đã bị vô hiệu hóa.');
        }
        if (user.role && (user.role.roleName === 'admin' || user.role.roleName === 'user')) {
            req.user.roleName = user.role.roleName;
            next();
        } else {
            return response(res, 403, 'Bạn không có quyền thực hiện hành động này.'); 
        }
    } catch (error) {
        console.error('Authorization authenticated user error:', error);
        return response(res, 500, 'Lỗi server nội bộ khi kiểm tra quyền.');
    }
};
// Middleware chỉ cho phép ADMIN
export const check_admin = async (req, res, next) => {
    console.log('check_admin middleware called');
    if (!req.user || !req.user.id) {
        console.log('No user or user.id found');
        return response(res, 401, 'Thông tin người dùng không hợp lệ trong token. Vui lòng đăng nhập lại.');
    }
    try {
        const user = await User.findById(req.user.id).populate('role');
        if (!user) {
            console.log('User not found');
            return response(res, 404, 'Người dùng không tồn tại.');
        }
        // Kiểm tra nếu tài khoản bị xóa mềm
        if (user.isDeleted) {
            console.log('User is deleted');
            return response(res, 403, 'Tài khoản của bạn đã bị vô hiệu hóa.');
        }
        console.log('User role:', user.role);
        if (user.role && user.role.roleName === 'admin') {
            req.user.roleName = user.role.roleName;
            next();
        } else {
            return response(res, 403, 'Bạn không có quyền truy cập chức năng này (chỉ dành cho Admin).');
        }
    } catch (error) {
        console.error('Authorization admin error:', error);
        return response(res, 500, 'Lỗi server nội bộ khi kiểm tra quyền admin.');
    }
};