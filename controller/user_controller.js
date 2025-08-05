// controllers/user_controller.js
import jwt from 'jsonwebtoken';
import User from '../models/user_model.js';
import Role from '../models/role_model.js';
import response from '../utils/response.js';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import crypto from 'crypto';
import path from 'path';
import { sendEmail, createAccountDeletionEmail } from '../utils/email.js';
import fs from 'fs';
import Review from '../models/review_model.js';

dotenv.config();

// Hàm tạo OTP 6 chữ số
const generateOtp = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

// Hàm tiện ích để làm sạch dữ liệu người dùng trước khi gửi về client
const cleanUserData = (userDoc) => {
    const userObj = userDoc.toObject();
    const { password, refreshTokens, resetPasswordToken, resetPasswordExpires, otp, otpExpires, passwordChangeToken, passwordChangeTokenExpires, pendingNewPassword, ...cleanedUser } = userObj;

    // Đảm bảo role luôn là object với id và name
    if (cleanedUser.role && typeof cleanedUser.role === 'object') {
        cleanedUser.role = {
            id: cleanedUser.role._id.toString(),
            name: cleanedUser.role.roleName
        };
    } else if (cleanedUser.role) {

        cleanedUser.role = null;
    } else {
        cleanedUser.role = null;
    }

    // Format deletedAt nếu có
    if (cleanedUser.deletedAt) {
        cleanedUser.deletedAt = new Date(cleanedUser.deletedAt).toISOString();
    }

    // Format deactivatedAt nếu có
    if (cleanedUser.deactivatedAt) {
        cleanedUser.deactivatedAt = new Date(cleanedUser.deactivatedAt).toISOString();
    }

    return cleanedUser;
};

const user_controller = {
    register: async (req, res) => {
        try {
            const { email, password, repeat_password } = req.body;
            const existingUser = await User.findOne({ email }); // Tìm cả user đã xóa mềm
            if (existingUser && !existingUser.isDeleted) {
                return response(res, 409, 'Email đã được đăng ký.');
            }
            if (existingUser && existingUser.isDeleted) {
                return response(res, 409, 'Email này đã tồn tại nhưng đang ở trạng thái đã xóa. Vui lòng liên hệ hỗ trợ để khôi phục.');
            }
            if (password !== repeat_password) {
                return response(res, 400, "Xác nhận mật khẩu không khớp.");
            }
            if (password.length < 6) { // Chỉ kiểm tra độ dài tối thiểu
                return response(res, 400, 'Mật khẩu phải có ít nhất 6 ký tự.');
            }

            const userRole = await Role.findOne({ roleName: 'user' });
            if (!userRole) {
                console.error('Role "user" not found in database. Please create it.');
                return response(res, 500, 'Lỗi cấu hình hệ thống: Vai trò người dùng không tồn tại.');
            }
            const newUser = new User({
                email,
                password,
                role: userRole._id,
                isActive: true,
                isDeleted: false
            });
            await newUser.save();
            const userData = cleanUserData(newUser);
            return response(res, 201, 'Đăng ký tài khoản thành công. Vui lòng đăng nhập.', { user: userData });
        } catch (error) {
            console.error('Register error:', error);
            return response(res, 500, 'Lỗi server nội bộ.');
        }
    },
    login: async (req, res) => {
        try {
            const { email, password } = req.body;
            const user = await User.findOne({ email }).populate('role');
            if (!user || !bcrypt.compareSync(password, user.password)) {
                return response(res, 401, 'Email hoặc mật khẩu không đúng.');
            }
            if (!user.isActive) {
                return response(res, 403, 'Tài khoản đã bị vô hiệu hóa. Vui lòng liên hệ hỗ trợ.');
            }
            if (user.isDeleted) {
                return response(res, 403, 'Tài khoản của bạn đã bị xóa. Vui lòng liên hệ hỗ trợ để khôi phục.');
            }
            const payload = { id: user._id, role: user.role.roleName };
            const accessToken = jwt.sign(payload, process.env.SECRET_KEY, { expiresIn: '2h' });
            const refreshToken = jwt.sign(payload, process.env.REFRESH_KEY, { expiresIn: '7d' });

            user.refreshTokens = user.refreshTokens || [];
            user.refreshTokens.push(refreshToken);
            await user.save();

            res.cookie('refreshToken', refreshToken, {
                httpOnly: true,
                sameSite: 'Strict',
                maxAge: 7 * 24 * 60 * 60 * 1000,
                secure: process.env.NODE_ENV === 'production'
            });
            const userResponse = cleanUserData(user);
            return response(res, 200, 'Đăng nhập thành công', {
                user: userResponse,
                accessToken
            });
        } catch (error) {
            console.error('Login error:', error);
            return response(res, 500, 'Lỗi server nội bộ.');
        }
    },
    refreshToken: async (req, res, next) => {
        console.log('[AUTH] Received request to refresh token...');
        try {
            const token = req.cookies.refreshToken;
            if (!token) return response(res, 401, 'Không có refresh token.');

            let decoded;
            try {
                decoded = jwt.verify(token, process.env.REFRESH_KEY);
            } catch (err) {
                res.clearCookie('refreshToken', {
                    httpOnly: true,
                    sameSite: 'Strict',
                    secure: process.env.NODE_ENV === 'production'
                });
                return response(res, 403, 'Refresh token không hợp lệ hoặc đã hết hạn. Vui lòng đăng nhập lại.');
            }

            const user = await User.findById(decoded.id).populate('role');
            if (!user || !user.refreshTokens.includes(token)) {
                res.clearCookie('refreshToken', {
                    httpOnly: true,
                    sameSite: 'Strict',
                    secure: process.env.NODE_ENV === 'production'
                });
                return response(res, 403, 'Refresh token không hợp lệ hoặc đã bị thu hồi. Vui lòng đăng nhập lại.');
            }
            if (!user.isActive || user.isDeleted) {
                res.clearCookie('refreshToken', {
                    httpOnly: true,
                    sameSite: 'Strict',
                    secure: process.env.NODE_ENV === 'production'
                });
                return response(res, 403, 'Tài khoản của bạn đã bị vô hiệu hóa hoặc bị xóa. Vui lòng đăng nhập lại.');
            }

            const payload = { id: user._id, role: user.role.roleName };
            const newAccessToken = jwt.sign(payload, process.env.SECRET_KEY, { expiresIn: '2h' }); // Tăng thời gian sống
            console.log('[AUTH] New access token generated successfully.');
            return response(res, 200, 'Cấp mới access token thành công', { accessToken: newAccessToken });
        } catch (error) {
            console.error('Refresh token error:', error);
            return response(res, 500, 'Lỗi server nội bộ khi làm mới token.');
        }
    },
    logout: async (req, res) => {
        try {
            const token = req.cookies.refreshToken;
            if (!token) return response(res, 200, 'Đăng xuất thành công.');

            let decoded;
            try {
                decoded = jwt.verify(token, process.env.REFRESH_KEY);
            } catch (err) {
                res.clearCookie('refreshToken', {
                    httpOnly: true,
                    sameSite: 'Strict',
                    secure: process.env.NODE_ENV === 'production'
                });
                return response(res, 200, 'Đăng xuất thành công (token đã hết hạn hoặc không hợp lệ).');
            }

            const user = await User.findById(decoded.id);
            if (user) {
                user.refreshTokens = user.refreshTokens.filter(t => t !== token);
                await user.save();
            }
            res.clearCookie('refreshToken', {
                httpOnly: true,
                sameSite: 'Strict',
                secure: process.env.NODE_ENV === 'production'
            });
            return response(res, 200, 'Đăng xuất thành công.');
        } catch (error) {
            console.error('Logout error:', error);
            return response(res, 500, 'Lỗi khi đăng xuất.');
        }
    },
    requestChangePasswordOtp: async (req, res) => {
        try {
            const userId = req.user.id;
            const { currentPassword, newPassword, confirmNewPassword } = req.body;

            const user = await User.findById(userId);
            if (!user) {
                return response(res, 404, 'Người dùng không tồn tại.');
            }
            if (user.isDeleted) {
                return response(res, 403, 'Tài khoản của bạn đã bị vô hiệu hóa.');
            }
            if (!bcrypt.compareSync(currentPassword, user.password)) {
                return response(res, 401, 'Mật khẩu hiện tại không đúng.');
            }
            if (newPassword.length < 6) {
                return response(res, 400, 'Mật khẩu mới phải có ít nhất 6 ký tự.');
            }
            if (newPassword !== confirmNewPassword) {
                return response(res, 400, 'Xác nhận mật khẩu mới không khớp.');
            }
            if (bcrypt.compareSync(newPassword, user.password)) {
                return response(res, 400, 'Mật khẩu mới không được trùng với mật khẩu hiện tại.');
            }

            // Lưu tạm mật khẩu mới (chưa hash, sẽ hash khi đổi thật)
            user.pendingNewPassword = newPassword;
            const otp = generateOtp();
            user.otp = otp;
            user.otpExpires = Date.now() + 10 * 60 * 1000;
            await user.save();

            const mailOptions = {
                to: user.email,
                subject: 'Mã OTP xác nhận đổi mật khẩu',
                html: `
                    <p>Mã OTP của bạn để xác nhận đổi mật khẩu là: <strong>${otp}</strong></p>
                    <p>Mã này sẽ hết hạn sau 10 phút. Vui lòng không chia sẻ mã này với bất kỳ ai.</p>
                    <p>Nếu bạn không yêu cầu đổi mật khẩu, vui lòng bỏ qua email này.</p>
                    <p>Trân trọng,</p>
                    <p>Đội ngũ hỗ trợ của bạn</p>
                `
            };
            await sendEmail(mailOptions.to, mailOptions.subject, '', mailOptions.html);

            return response(res, 200, 'Mã OTP đã được gửi đến email của bạn. Vui lòng kiểm tra hộp thư đến.');
        } catch (error) {
            console.error('Request change password OTP error:', error);
            return response(res, 500, 'Lỗi server nội bộ khi yêu cầu đổi mật khẩu.');
        }
    },
    verifyOtpForPasswordChange: async (req, res) => {
        try {
            const userId = req.user.id;
            const { otp } = req.body;

            const user = await User.findById(userId);
            if (!user) {
                return response(res, 404, 'Người dùng không tồn tại.');
            }
            if (user.isDeleted) {
                return response(res, 403, 'Tài khoản của bạn đã bị vô hiệu hóa.');
            }

            if (!user.otp || user.otp !== otp || user.otpExpires < Date.now()) {
                return response(res, 400, 'Mã OTP không hợp lệ hoặc đã hết hạn.');
            }

            const passwordChangeToken = crypto.randomBytes(32).toString('hex');
            user.passwordChangeToken = passwordChangeToken;
            user.passwordChangeTokenExpires = Date.now() + 5 * 60 * 1000; // Token hết hạn sau 5 phút

            user.otp = undefined;
            user.otpExpires = undefined;

            await user.save();

            return response(res, 200, 'Xác thực OTP thành công. Bạn có thể tiến hành đổi mật khẩu.', { passwordChangeToken });
        } catch (error) {
            console.error('Verify OTP for password change error:', error);
            return response(res, 500, 'Lỗi server nội bộ khi xác thực OTP.');
        }
    },
    confirmChangePassword: async (req, res) => {
        try {
            const userId = req.user.id;
            const { otp } = req.body;

            const user = await User.findById(userId);
            if (!user) {
                return response(res, 404, 'Người dùng không tồn tại.');
            }
            if (user.isDeleted) {
                return response(res, 403, 'Tài khoản của bạn đã bị vô hiệu hóa.');
            }
            if (!user.otp || user.otp !== otp || user.otpExpires < Date.now()) {
                return response(res, 400, 'Mã OTP không hợp lệ hoặc đã hết hạn.');
            }
            if (!user.pendingNewPassword) {
                return response(res, 400, 'Không tìm thấy thông tin đổi mật khẩu. Vui lòng thực hiện lại quy trình.');
            }
            // Đổi mật khẩu (sẽ được hash bởi pre-save hook)
            user.password = user.pendingNewPassword;
            user.pendingNewPassword = null;
            user.otp = null;
            user.otpExpires = null;
            user.refreshTokens = [];
            await user.save();

            res.clearCookie('refreshToken', {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'Strict'
            });

            return response(res, 200, 'Mật khẩu đã được đổi thành công! Vui lòng đăng nhập lại.');
        } catch (error) {
            console.error('Confirm change password error:', error);
            return response(res, 500, 'Lỗi server nội bộ khi xác nhận đổi mật khẩu.');
        }
    },
    forgotPassword: async (req, res) => {
        try {
            const { email } = req.body;
            const user = await User.findOne({ email, isDeleted: false });

            if (!user) {
                return response(res, 400, 'Email không tồn tại trong hệ thống hoặc đã bị xóa.');
            }

            const otp = generateOtp();
            user.otp = otp;
            user.otpExpires = Date.now() + 10 * 60 * 1000;

            user.passwordChangeToken = undefined;
            user.passwordChangeTokenExpires = undefined;

            await user.save();

            const mailOptions = {
                to: user.email,
                subject: 'Mã OTP để đặt lại mật khẩu của bạn',
                html: `
                    <p>Mã OTP của bạn để đặt lại mật khẩu là: <strong>${otp}</strong></p>
                    <p>Mã này sẽ hết hạn sau 10 phút. Vui lòng không chia sẻ mã này với bất kỳ ai.</p>
                    <p>Nếu bạn không yêu cầu đặt lại mật khẩu, vui lòng bỏ qua email này.</p>
                    <p>Trân trọng,</p>
                    <p>Đội ngũ hỗ trợ của bạn</p>
                `
            };
            await sendEmail(mailOptions.to, mailOptions.subject, '', mailOptions.html);

            return response(res, 200, 'Mã OTP đã được gửi đến email của bạn. Vui lòng kiểm tra hộp thư đến.');
        } catch (error) {
            console.error('Forgot password error:', error);
            return response(res, 500, 'Lỗi server nội bộ khi xử lý yêu cầu quên mật khẩu.');
        }
    },
    verifyOtpForForgotPassword: async (req, res) => {
        try {
            const { email, otp } = req.body;

            const user = await User.findOne({ email, isDeleted: false });
            if (!user) {
                return response(res, 404, 'Email không tồn tại trong hệ thống.');
            }

            if (!user.otp || user.otp !== otp || user.otpExpires < Date.now()) {
                return response(res, 400, 'Mã OTP không hợp lệ hoặc đã hết hạn.');
            }

            const passwordChangeToken = crypto.randomBytes(32).toString('hex');
            user.passwordChangeToken = passwordChangeToken;
            user.passwordChangeTokenExpires = Date.now() + 5 * 60 * 1000; // Token hết hạn sau 5 phút

            user.otp = undefined;
            user.otpExpires = undefined;

            await user.save();

            return response(res, 200, 'Xác thực OTP thành công. Bạn có thể tiến hành đặt lại mật khẩu.', { passwordChangeToken });
        } catch (error) {
            console.error('Verify OTP for forgot password error:', error);
            return response(res, 500, 'Lỗi server nội bộ khi xác thực OTP.');
        }
    },
    resetPassword: async (req, res) => {
        try {
            const { email, passwordChangeToken, newPassword, confirmNewPassword } = req.body;
            console.log("Reset Password Request Body:", req.body); // Để debug chính xác

            const user = await User.findOne({
                email,
                passwordChangeToken: passwordChangeToken,
                passwordChangeTokenExpires: { $gt: Date.now() },
                isDeleted: false
            }).populate('role'); // Populate role để dùng trong cleanUserData nếu cần

            if (!user) {
                console.log("User not found or token invalid/expired for:", { email, passwordChangeToken });
                return response(res, 400, 'Token đặt lại mật khẩu không hợp lệ, đã hết hạn hoặc email không đúng. Vui lòng yêu cầu lại quy trình quên mật khẩu.');
            }

            if (newPassword !== confirmNewPassword) {
                return response(res, 400, 'Mật khẩu mới và xác nhận mật khẩu không khớp.');
            }

            if (newPassword.length < 6) {
                return response(res, 400, 'Mật khẩu mới phải có ít nhất 6 ký tự.');
            }

            user.password = newPassword;
            user.otp = undefined;
            user.otpExpires = undefined;
            user.passwordChangeToken = undefined;
            user.passwordChangeTokenExpires = undefined;
            user.refreshTokens = [];
            await user.save();

            res.clearCookie('refreshToken', {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'Strict'
            });

            return response(res, 200, 'Mật khẩu đã được đặt lại thành công. Vui lòng đăng nhập lại.');
        } catch (error) {
            console.error('Reset password error:', error);
            return response(res, 500, 'Lỗi server nội bộ khi đặt lại mật khẩu.');
        }
    },
    updateProfile: async (req, res) => {
        try {
            const userId = req.user.id;
            const { fullName, phoneNumber, username } = req.body;
            let profilePicturePath = req.file ? `/uploads/${req.file.filename}` : undefined;

            const user = await User.findById(userId);
            if (!user) {
                return response(res, 404, 'Người dùng không tồn tại.');
            }
            if (user.isDeleted) {
                return response(res, 403, 'Tài khoản của bạn đã bị vô hiệu hóa.');
            }

            // Kiểm tra username trùng lặp nếu có thay đổi
            if (username !== undefined && username !== user.username) {
                const existingUser = await User.findOne({ username, _id: { $ne: userId } });
                if (existingUser) {
                    return response(res, 409, 'Tên đăng nhập đã được sử dụng bởi người dùng khác.');
                }
            }

            if (fullName !== undefined) user.fullName = fullName;
            if (phoneNumber !== undefined) user.phoneNumber = phoneNumber;
            if (username !== undefined) user.username = username; // Cập nhật username

            if (profilePicturePath !== undefined) {
                if (user.profilePicture && user.profilePicture !== profilePicturePath && !user.profilePicture.startsWith('/default-avatars/')) {
                    const oldPath = path.join(process.cwd(), user.profilePicture);
                    if (fs.existsSync(oldPath)) {
                        fs.unlink(oldPath, (err) => {
                            if (err) console.error("Failed to delete old profile picture:", oldPath, err);
                        });
                    }
                }
                user.profilePicture = profilePicturePath;
            }

            await user.save();

            const userData = cleanUserData(user);
            return response(res, 200, 'Hồ sơ cá nhân đã được cập nhật thành công!', { user: userData });
        } catch (error) {
            console.error('Update profile error:', error);
            if (error.message.includes('Chỉ cho phép ảnh')) {
                return response(res, 400, error.message);
            }
            return response(res, 500, 'Lỗi server nội bộ khi cập nhật hồ sơ cá nhân.');
        }
    },
    // THÊM MỚI: API riêng cho Admin tạo người dùng
    createUserByAdmin: async (req, res) => {
        try {
            const { email, password, fullName, phoneNumber, roleId } = req.body;
            // req.file sẽ chứa profilePicture nếu có

            const existingUser = await User.findOne({ email });
            if (existingUser && !existingUser.isDeleted) {
                return response(res, 409, 'Email đã được đăng ký.');
            }
            if (password.length < 6) {
                return response(res, 400, 'Mật khẩu phải có ít nhất 6 ký tự.');
            }
            const role = await Role.findById(roleId);
            if (!role) {
                return response(res, 400, 'Vai trò không hợp lệ.');
            }

            const newUser = new User({
                email,
                password,
                fullName,
                phoneNumber,
                role: role._id, // Lưu ObjectId của role
                profilePicture: req.file ? `/uploads/${req.file.filename}` : undefined,
                isActive: true,
                isDeleted: false
            });
            await newUser.save();
            const userData = cleanUserData(newUser);
            return response(res, 201, 'Tạo người dùng thành công', { user: userData });
        } catch (error) {
            console.error('Create user by admin error:', error);
            return response(res, 500, 'Lỗi server nội bộ khi tạo người dùng.');
        }
    },
    // THÊM MỚI: API riêng cho Admin cập nhật thông tin người dùng (bao gồm cả role, trạng thái)
    updateUserByAdmin: async (req, res) => {
        try {
            const { id } = req.params; // Lấy ID của user cần cập nhật từ params
            const { email, fullName, phoneNumber, roleId, username, isActive, isDeleted } = req.body;
            let profilePicturePath = req.file ? `/uploads/${req.file.filename}` : undefined;

            const user = await User.findById(id).populate('role');
            if (!user) {
                return response(res, 404, 'Người dùng không tồn tại.');
            }

            // Cập nhật các trường
            if (email !== undefined && user.email !== email) {
                const existingEmail = await User.findOne({ email, _id: { $ne: id } });
                if (existingEmail && !existingEmail.isDeleted) {
                    return response(res, 409, 'Email đã được đăng ký bởi người dùng khác.');
                }
                user.email = email;
            }
            if (fullName !== undefined) user.fullName = fullName;
            if (phoneNumber !== undefined) user.phoneNumber = phoneNumber;
            if (username !== undefined) user.username = username;

            // Cập nhật Role
            if (roleId !== undefined && user.role._id.toString() !== roleId) {
                const newRole = await Role.findById(roleId);
                if (!newRole) {
                    return response(res, 400, 'Vai trò không hợp lệ.');
                }
                user.role = newRole._id;
            }

            // Cập nhật trạng thái isActive và isDeleted
            if (isActive !== undefined) user.isActive = isActive;
            if (isDeleted !== undefined) user.isDeleted = isDeleted;


            if (profilePicturePath !== undefined) {
                if (user.profilePicture && !user.profilePicture.startsWith('/default-avatars/')) {
                    const oldPath = path.join(process.cwd(), user.profilePicture);
                    if (fs.existsSync(oldPath)) {
                        fs.unlink(oldPath, (err) => {
                            if (err) console.error("Failed to delete old profile picture:", oldPath, err);
                        });
                    }
                }
                user.profilePicture = profilePicturePath;
            }

            await user.save();
            const userData = cleanUserData(user); // Đảm bảo cleanUserData populate role đầy đủ
            return response(res, 200, 'Cập nhật người dùng thành công.', { user: userData });
        } catch (error) {
            console.error('Update user by admin error:', error);
            if (error.message.includes('Chỉ cho phép ảnh')) {
                return response(res, 400, error.message);
            }
            return response(res, 500, 'Lỗi server nội bộ khi cập nhật người dùng.');
        }
    },
    getAllUsers: async (req, res) => {
        try {
            const { page = 1, limit = 10, filterBy = '' } = req.query;
            const skip = (page - 1) * limit;
            let query = filterBy === 'all' ? {} : { isDeleted: false };
            if (filterBy === 'active') query.isActive = true;
            if (filterBy === 'inactive') query.isActive = false;
            if (filterBy === 'deleted') query.isDeleted = true;

            const users = await User.find(query).populate('role').skip(skip).limit(parseInt(limit));

            const total = await User.countDocuments(query);
            return response(res, 200, 'Lấy danh sách người dùng thành công', {
                users,
                pagination: {
                    currentPage: parseInt(page),
                    totalPages: Math.ceil(total / limit),
                    itemsPerPage: parseInt(limit),
                    totalItems: total,
                },
            });
        } catch (error) {
            return response(res, 500, 'Lỗi server nội bộ');
        }
    },
    getUserById: async (req, res) => {
        try {
            const { id } = req.params;
            const includeDeleted = req.query.includeDeleted === 'true';
            const query = includeDeleted ? { _id: id } : { _id: id, isDeleted: false };

            const user = await User.findOne(query).populate('role');
            if (!user) {
                return response(res, 404, 'Người dùng không tồn tại hoặc đã bị xóa.');
            }
            const userObj = cleanUserData(user);
            return response(res, 200, 'Lấy thông tin người dùng thành công.', { user: userObj });
        } catch (error) {
            console.error('Get user by ID error:', error);
            return response(res, 500, 'Lỗi server nội bộ khi lấy thông tin người dùng.');
        }
    },
    softDeleteUser: async (req, res) => {
        try {
            const { id } = req.params;
            const { reason } = req.body; // Thêm tham số reason

            const user = await User.findById(id);
            if (!user) {
                return response(res, 404, 'Người dùng không tồn tại.');
            }
            if (user.isDeleted) {
                return response(res, 400, 'Người dùng này đã bị xóa mềm trước đó.');
            }

            user.isDeleted = true;
            user.refreshTokens = [];

            // Nếu có reason thì lưu thông tin
            if (reason) {
                user.deleteReason = reason;
                user.deletedAt = new Date();
            }

            await user.save();

            // Ẩn tất cả review của user này (nếu chưa bị ẩn), gắn lý do user_deleted
            await Review.updateMany(
                { userId: id, isHidden: false },
                { $set: { isHidden: true, hiddenReason: 'user_deleted' } }
            );

            // Gửi email nếu có reason
            let emailSent = false;
            if (reason) {
                const websiteName = process.env.WEBSITE_NAME || 'BookStore';
                const supportEmail = process.env.SUPPORT_EMAIL || 'support@bookstore.com';
                const supportPhone = process.env.SUPPORT_PHONE || '0123 456 789';

                const emailHtml = createAccountDeletionEmail(
                    user.fullName || 'Người dùng',
                    websiteName,
                    user.deletedAt,
                    user.deleteReason,
                    supportEmail,
                    supportPhone
                );

                emailSent = await sendEmail(
                    user.email,
                    `Thông báo xóa tài khoản - ${websiteName}`,
                    '',
                    emailHtml
                );
            }

            const userData = cleanUserData(user);
            const message = reason
                ? (emailSent
                    ? 'Người dùng đã được xóa mềm thành công và email thông báo đã được gửi.'
                    : 'Người dùng đã được xóa mềm thành công nhưng không thể gửi email thông báo.')
                : 'Người dùng đã được xóa mềm thành công.';

            return response(res, 200, message, {
                user: userData,
                emailSent: emailSent,
                hasReason: !!reason
            });
        } catch (error) {
            console.error('Soft delete user error:', error);
            return response(res, 500, 'Lỗi server nội bộ khi xóa mềm người dùng.');
        }
    },
    restoreUser: async (req, res) => {
        try {
            const { id } = req.params;

            const user = await User.findById(id);
            if (!user) {
                return response(res, 404, 'Người dùng không tồn tại.');
            }
            if (!user.isDeleted) {
                return response(res, 400, 'Người dùng này chưa bị xóa mềm.');
            }

            user.isDeleted = false;
            user.deleteReason = null; // Xóa lý do xóa
            user.deletedAt = null; // Xóa thời gian xóa
            // KHÔNG tự động set isActive = true để giữ nguyên trạng thái ban đầu
            await user.save();

            // Hiện lại các review bị ẩn do user_deleted
            await Review.updateMany(
                { userId: id, isHidden: true, hiddenReason: 'user_deleted' },
                { $set: { isHidden: false }, $unset: { hiddenReason: '' } }
            );

            const userData = cleanUserData(user);
            const message = user.isActive
                ? 'Người dùng đã được khôi phục thành công và đang active.'
                : 'Người dùng đã được khôi phục thành công nhưng vẫn inactive. Cần kích hoạt thêm.';

            return response(res, 200, message, { user: userData });
        } catch (error) {
            console.error('Restore user error:', error);
            return response(res, 500, 'Lỗi server nội bộ khi khôi phục người dùng.');
        }
    },
    deleteUser: async (req, res) => {
        try {
            const { id } = req.params;

            if (req.user.id === id) {
                return response(res, 400, 'Bạn không thể xóa tài khoản của chính mình khi đang đăng nhập.');
            }

            const user = await User.findByIdAndDelete(id);
            if (!user) {
                return response(res, 404, 'Người dùng không tồn tại.');
            }

            return response(res, 200, 'Người dùng đã được xóa cứng thành công.');
        } catch (error) {
            console.error('Delete user error:', error);
            return response(res, 500, 'Lỗi server nội bộ khi xóa cứng người dùng.');
        }
    },

    toggleUserActiveStatus: async (req, res) => {
        try {
            const { id } = req.params;
            const { isActive, reason } = req.body; // Thêm tham số reason

            const user = await User.findById(id);
            if (!user) {
                return response(res, 404, 'Người dùng không tồn tại.');
            }


            user.isActive = isActive;

            // Lưu lý do vô hiệu hóa nếu có
            if (reason && !isActive) {
                user.deactivationReason = reason;
                user.deactivatedAt = new Date();
            } else if (isActive) {
                // Nếu kích hoạt lại thì xóa lý do vô hiệu hóa
                user.deactivationReason = null;
                user.deactivatedAt = null;
            }

            await user.save();

            // Gửi email thông báo vô hiệu hóa nếu có reason và đang vô hiệu hóa
            let emailSent = false;
            if (reason && !isActive) {
                const websiteName = process.env.WEBSITE_NAME || 'BookStore';
                const supportEmail = process.env.SUPPORT_EMAIL || 'support@bookstore.com';
                const supportPhone = process.env.SUPPORT_PHONE || '0123 456 789';

                const deactivationDate = new Date();
                const emailHtml = `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9f9f9;">
                        <div style="background-color: #ffffff; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                            <h2 style="color: #333; text-align: center; margin-bottom: 30px;">Thông Báo Vô Hiệu Hóa Tài Khoản</h2>

                            <p style="color: #555; font-size: 16px; line-height: 1.6;">
                                Chào <strong>${user.fullName || 'Người dùng'}</strong>,
                            </p>

                            <p style="color: #555; font-size: 16px; line-height: 1.6;">
                                Chúng tôi thông báo rằng tài khoản của bạn tại <strong>${websiteName}</strong> đã bị vô hiệu hóa vào <strong>${deactivationDate.toLocaleString('vi-VN')}</strong>.
                            </p>

                            ${reason ? `<p style="color: #555; font-size: 16px; line-height: 1.6;">
                                <strong>Lý do:</strong> ${reason}
                            </p>` : ''}

                            <div style="background-color: #fff3cd; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #ffc107;">
                                <p style="color: #333; font-size: 16px; line-height: 1.6; margin: 0;">
                                    ⚠️ <strong>Tài khoản của bạn đã bị vô hiệu hóa.</strong> Bạn không thể đăng nhập vào hệ thống cho đến khi tài khoản được kích hoạt lại.
                                </p>
                            </div>

                            <p style="color: #555; font-size: 16px; line-height: 1.6;">
                                Nếu bạn có thắc mắc hoặc muốn kích hoạt lại tài khoản, hãy liên hệ với chúng tôi tại:
                            </p>

                            <div style="background-color: #e8f4fd; padding: 15px; border-radius: 8px; margin: 15px 0;">
                                <p style="color: #333; font-size: 16px; line-height: 1.6; margin: 5px 0;">
                                    📧 <strong>Email:</strong> ${supportEmail}
                                </p>
                                <p style="color: #333; font-size: 16px; line-height: 1.6; margin: 5px 0;">
                                    📞 <strong>Điện thoại:</strong> ${supportPhone}
                                </p>
                            </div>

                            <p style="color: #555; font-size: 16px; line-height: 1.6;">
                                Thân mến,<br>
                                <strong>Đội ngũ ${websiteName}</strong>
                            </p>
                        </div>
                    </div>
                `;

                emailSent = await sendEmail(
                    user.email,
                    `Thông báo vô hiệu hóa tài khoản - ${websiteName}`,
                    '',
                    emailHtml
                );
            }
            const statusMessage = isActive ? 'kích hoạt' : 'vô hiệu hóa';
            const userData = cleanUserData(user);
            let message = `Người dùng đã được ${statusMessage} thành công.`;
            if (reason && !isActive) {
                message = emailSent
                    ? `Người dùng đã được ${statusMessage} thành công và email thông báo đã được gửi.`
                    : `Người dùng đã được ${statusMessage} thành công nhưng không thể gửi email thông báo.`;
            }

            return response(res, 200, message, {
                user: userData,
                emailSent: emailSent,
                hasReason: !!reason
            });
        } catch (error) {
            console.error('Toggle user active status error:', error);
            return response(res, 500, 'Lỗi server nội bộ khi cập nhật trạng thái người dùng.');
        }
    },
    getMe: async (req, res) => {
        try {
            const userId = req.user.id;
            const user = await User.findById(userId).populate('role');

            if (!user) {
                return response(res, 404, 'Thông tin người dùng không tồn tại.');
            }
            if (user.isDeleted || !user.isActive) {
                return response(res, 403, 'Tài khoản của bạn đã bị vô hiệu hóa hoặc xóa.');
            }

            const userObj = cleanUserData(user);
            return response(res, 200, 'Lấy thông tin hồ sơ thành công.', { user: userObj });
        } catch (error) {
            console.error('Get profile error:', error);
            return response(res, 500, 'Lỗi server nội bộ khi lấy thông tin hồ sơ.');
        }
    },
    getAllRoles: async (req, res) => {
        try {
            const roles = await Role.find({});
            return response(res, 200, 'Lấy danh sách vai trò thành công.', { roles });
        } catch (error) {
            console.error('Get all roles error:', error);
            return response(res, 500, 'Lỗi server nội bộ khi lấy danh sách vai trò.');
        }
    },
    resendChangePasswordOtp: async (req, res) => {
        try {
            const userId = req.user.id;
            const user = await User.findById(userId);
            if (!user) {
                return response(res, 404, 'Người dùng không tồn tại.');
            }
            if (user.isDeleted) {
                return response(res, 403, 'Tài khoản của bạn đã bị vô hiệu hóa.');
            }
            // Gửi lại OTP mới
            const otp = generateOtp();
            user.otp = otp;
            user.otpExpires = Date.now() + 10 * 60 * 1000;
            await user.save();
            const mailOptions = {
                to: user.email,
                subject: 'Mã OTP xác nhận đổi mật khẩu',
                html: `
                    <p>Mã OTP của bạn để xác nhận đổi mật khẩu là: <strong>${otp}</strong></p>
                    <p>Mã này sẽ hết hạn sau 10 phút. Vui lòng không chia sẻ mã này với bất kỳ ai.</p>
                    <p>Nếu bạn không yêu cầu đổi mật khẩu, vui lòng bỏ qua email này.</p>
                    <p>Trân trọng,</p>
                    <p>Đội ngũ hỗ trợ của bạn</p>
                `
            };
            await sendEmail(mailOptions.to, mailOptions.subject, '', mailOptions.html);
            return response(res, 200, 'Mã OTP mới đã được gửi đến email của bạn. Vui lòng kiểm tra hộp thư đến.');
        } catch (error) {
            console.error('Resend change password OTP error:', error);
            return response(res, 500, 'Lỗi server nội bộ khi gửi lại mã OTP.');
        }
    },

    // Lấy tổng doanh thu
    getTotalRevenue: async (req, res) => {
        try {
            const axios = (await import('axios')).default;
            const ORDER_SERVICE = process.env.ORDER_SERVICE_URL || 'http://localhost:8001';

            // Gọi API từ orderService để lấy tổng doanh thu
            const orderResponse = await axios.get(`${ORDER_SERVICE}/api/order/total-revenue`, {
                headers: { Authorization: req.headers.authorization }
            });

            return response(res, 200, 'Lấy tổng doanh thu thành công', {
                totalRevenue: orderResponse.data.data.totalRevenue || 0
            });
        } catch (error) {
            console.error('Get total revenue error:', error);
            return response(res, 500, 'Lỗi server nội bộ khi lấy tổng doanh thu.');
        }
    },

    // Lấy số lượng tài khoản đã xóa mềm
    getDeletedUsersCount: async (req, res) => {
        try {
            const deletedUsersCount = await User.countDocuments({ isDeleted: true });

            return response(res, 200, 'Lấy số lượng tài khoản đã xóa thành công', {
                deletedUsersCount
            });
        } catch (error) {
            console.error('Get deleted users count error:', error);
            return response(res, 500, 'Lỗi server nội bộ khi lấy số lượng tài khoản đã xóa.');
        }
    }

};

export default user_controller;