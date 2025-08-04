import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
const Schema = mongoose.Schema;

const UserSchema = new Schema({

    password: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        index: true,
        trim: true,
        validate: {
            validator: (v) => /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(v),
            message: 'Invalid email format'
        }
    },
    fullName: {
        type: String,
        trim: true
    },
    phoneNumber: {
        type: String,
        validate: {
            validator: (v) => /^\+?[\d\s-]{9,}$/.test(v),
            message: 'Invalid phone number'
        }
    },
    profilePicture: {
        type: String,
        default: null
    },
    role: {
        type: Schema.Types.ObjectId,
        ref: 'Role',
        required: true,
        index: true
    },
    isActive: { // Trạng thái kích hoạt tài khoản (có thể dùng để khóa/mở khóa)
        type: Boolean,
        default: true
    },
    isDeleted: { // Thêm trường xóa mềm
        type: Boolean,
        default: false,
        index: true
    },
    deleteReason: { // Lý do xóa tài khoản
        type: String,
        default: null
    },
    deletedAt: { // Thời gian xóa tài khoản
        type: Date,
        default: null
    },
    deactivationReason: { // Lý do vô hiệu hóa tài khoản
        type: String,
        default: null
    },
    deactivatedAt: { // Thời gian vô hiệu hóa tài khoản
        type: Date,
        default: null
    },
    otp: { // OTP cho xác thực đổi mật khẩu và quên mật khẩu
        type: String,
        default: null
    },
    otpExpires: { // Thời gian hết hạn của OTP
        type: Date,
        default: null
    },
    refreshTokens: {
        type: [String],
        default: []
    },
    passwordChangeToken: {
        type: String,
        default: null
    },
    passwordChangeTokenExpires: {
        type: Date,
        default: null
    },
    pendingNewPassword: {
        type: String,
        default: null
    },
}, { timestamps: true });

UserSchema.pre('save', async function (next) {
    if (this.isModified('password')) { // Chỉ hash khi password được sửa đổi
        try {
            this.password = await bcrypt.hash(this.password, 10);
            next();
        } catch (error) {
            next(error);
        }
    } else {
        next();
    }
});

const User = mongoose.model('User', UserSchema);
export default User;
