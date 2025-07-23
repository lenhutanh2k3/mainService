// controllers/user_controller.js
import jwt from 'jsonwebtoken';
import User from '../models/user_model.js';
import Role from '../models/role_model.js';
import response from '../utils/response.js';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import crypto from 'crypto';
import path from 'path';
import { sendEmail } from '../utils/email.js';
import fs from 'fs';

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
            id: cleanedUser.role._id.toString(), // Chuyển ObjectId sang string
            name: cleanedUser.role.roleName
        };
    } else if (cleanedUser.role) { // Trường hợp role là ObjectId nhưng chưa được populate
        // Có thể cần thêm logic populate role nếu không muốn gọi lại DB mỗi lần cleanData
        // Hiện tại, nếu không phải object, ta sẽ giả định không có role hoặc lỗi.
        cleanedUser.role = null;
    } else {
        cleanedUser.role = null;
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
            if (password.length < 6) { // Thêm validation độ dài mật khẩu cho đăng ký
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
            console.log(user);
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
            const accessToken = jwt.sign(payload, process.env.SECRET_KEY, { expiresIn: '30m' });
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
            const newAccessToken = jwt.sign(payload, process.env.SECRET_KEY, { expiresIn: '30m' }); // Tăng thời gian sống
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

            // Validate mật khẩu mạnh cho reset password
            const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]).{8,}$/;
            if (newPassword.length < 8) {
                return response(res, 400, 'Mật khẩu mới phải có ít nhất 8 ký tự.');
            }
            if (!strongPasswordRegex.test(newPassword)) {
                return response(res, 400, 'Mật khẩu mới phải có ít nhất 1 chữ hoa, 1 chữ thường, 1 số và 1 ký tự đặc biệt.');
            }

            user.password = newPassword; // Mongoose pre-save hook sẽ tự hash
            user.otp = undefined;
            user.otpExpires = undefined;
            user.passwordChangeToken = undefined;
            user.passwordChangeTokenExpires = undefined;
            user.refreshTokens = []; // Xóa tất cả session cũ
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

            const user = await User.findById(id);
            if (!user) {
                return response(res, 404, 'Người dùng không tồn tại.');
            }
            if (user.isDeleted) {
                return response(res, 400, 'Người dùng này đã bị xóa mềm trước đó.');
            }

            user.isDeleted = true;
            user.isActive = false;
            user.refreshTokens = [];
            await user.save();

            const userData = cleanUserData(user); // Trả về user đã cập nhật trạng thái
            return response(res, 200, 'Người dùng đã được xóa mềm thành công.', { user: userData });
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
            user.isActive = true;
            await user.save();

            const userData = cleanUserData(user); // Trả về user đã cập nhật trạng thái
            return response(res, 200, 'Người dùng đã được khôi phục thành công.', { user: userData });
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
            const { isActive } = req.body;

            const user = await User.findById(id);
            if (!user) {
                return response(res, 404, 'Người dùng không tồn tại.');
            }
            if (user.isDeleted) {
                return response(res, 400, 'Không thể thay đổi trạng thái tài khoản đã bị xóa. Vui lòng khôi phục trước.');
            }
            user.isActive = isActive;
            await user.save();
            const userData = cleanUserData(user);
            return response(res, 200, 'Cập nhật trạng thái người dùng thành công.', { user: userData });
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
    }
};

export default user_controller;