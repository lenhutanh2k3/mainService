import mongoose from 'mongoose';

const Schema = mongoose.Schema;

const ReviewSchema = new Schema({
    userId: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        index: true
    },
    bookId: {
        type: Schema.Types.ObjectId,
        required: true,
        index: true
    },
    orderId: {
        type: Schema.Types.ObjectId,
        ref: 'Order',
        required: true,
        index: true
    },
    rating: {
        type: Number,
        required: true,
        min: 1,
        max: 5,
        validate: {
            validator: Number.isInteger,
            message: 'Rating must be an integer'
        }
    },
    comment: {
        type: String,
        required: true,
        trim: true,
        minlength: [1, 'Comment cannot be empty'],
        maxlength: [1000, 'Comment cannot exceed 1000 characters']
    },
    isHidden: {
        type: Boolean,
        default: false,
        index: true
    },
    hiddenReason: {
        type: String,
        enum: ['user_deleted', 'user_action', 'admin_action'],
        default: undefined
    },
    helpfulCount: {
        type: Number,
        default: 0
    }
}, {
    timestamps: true,
    // Tạo compound index để đảm bảo mỗi user chỉ đánh giá một lần cho mỗi sách trong một đơn hàng
    indexes: [
        { userId: 1, bookId: 1, orderId: 1, unique: true },
        { status: 1, createdAt: -1 },
        { rating: 1, createdAt: -1 }
    ]
});

// Virtual để lấy thông tin user
ReviewSchema.virtual('user', {
    ref: 'User',
    localField: 'userId',
    foreignField: '_id',
    justOne: true
});

// Virtual để lấy thông tin order
ReviewSchema.virtual('order', {
    ref: 'Order',
    localField: 'orderId',
    foreignField: '_id',
    justOne: true
});

// Virtual để lấy thông tin book (sẽ được populate từ bookService)
ReviewSchema.virtual('book', {
    ref: 'Book',
    localField: 'bookId',
    foreignField: '_id',
    justOne: true
});

// Đảm bảo virtual fields được serialize khi chuyển đổi thành JSON
ReviewSchema.set('toJSON', { virtuals: true });
ReviewSchema.set('toObject', { virtuals: true });

// Middleware để cập nhật rating trung bình của sách
ReviewSchema.post('save', async function (doc) {
    try {
        // Gọi API đến bookService để cập nhật rating trung bình
        const axios = (await import('axios')).default;
        const BOOK_SERVICE_URL = process.env.BOOK_SERVICE_URL || 'http://localhost:8000';

        await axios.post(`${BOOK_SERVICE_URL}/api/books/${doc.bookId}/update-rating`, {
            reviewId: doc._id,
            rating: doc.rating,
            action: 'add'
        });
    } catch (error) {
        console.error('Error updating book rating:', error);
    }
});

ReviewSchema.post('findOneAndUpdate', async function (doc) {
    if (doc && doc.rating) {
        try {
            const axios = (await import('axios')).default;
            const BOOK_SERVICE_URL = process.env.BOOK_SERVICE_URL || 'http://localhost:8000';

            await axios.post(`${BOOK_SERVICE_URL}/api/books/${doc.bookId}/update-rating`, {
                reviewId: doc._id,
                rating: doc.rating,
                action: 'update'
            });
        } catch (error) {
            console.error('Error updating book rating:', error);
        }
    }
});

ReviewSchema.post('findOneAndDelete', async function (doc) {
    if (doc) {
        try {
            const axios = (await import('axios')).default;
            const BOOK_SERVICE_URL = process.env.BOOK_SERVICE_URL || 'http://localhost:8000';

            await axios.post(`${BOOK_SERVICE_URL}/api/books/${doc.bookId}/update-rating`, {
                reviewId: doc._id,
                rating: doc.rating,
                action: 'remove'
            });
        } catch (error) {
            console.error('Error updating book rating:', error);
        }
    }
});

const Review = mongoose.model('Review', ReviewSchema);
export default Review;