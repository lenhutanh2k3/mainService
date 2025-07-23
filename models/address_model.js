import mongoose from 'mongoose';
const Schema = mongoose.Schema;

const ShippingAddressSchema = new Schema({
    userId: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        index: true
    },
    address: {
        type: String,
        required: true,
        trim: true
    },
    fullName: {
        type: String,
        required: true,
        trim: true
    },
    phoneNumber: {
        type: String,
        required: true,
        validate: {
            validator: (v) => /^\+?[\d\s-]{9,}$/.test(v),
            message: 'Invalid phone number'
        }
    },
    status: {
        type: String,
        enum: ['active', 'inactive'],
        default: 'active'
    },
    ward: {
        type: String,
        required: true,
        trim: true
    },
    district: {
        type: String,
        required: true,
        trim: true
    },
    city: {
        type: String,
        required: true,
        trim: true
    },
    addressType: {
        type: String,
        enum: ['home', 'office', 'other'],
        default: 'home'
    },
    isDefault: {
        type: Boolean,
        default: false,
        index: true
    }
}, {
    timestamps: true
});

export default mongoose.model('ShippingAddress', ShippingAddressSchema); 