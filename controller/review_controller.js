import Review from '../models/review_model.js';
import response from '../utils/response.js';
import axios from 'axios';
import mongoose from 'mongoose';

const ORDER_SERVICE = process.env.ORDER_SERVICE || 'http://localhost:8001';
const BOOK_SERVICE = process.env.BOOK_SERVICE_URL || 'http://localhost:8000';

const review_controller = {
    // Tạo đánh giá mới
    createReview: async (req, res, next) => {
        try {
            const userId = req.user.id;
            const { bookId, orderId, rating, comment } = req.body;

            // Validation
            if (!bookId || !orderId || !rating || !comment) {
                throw new Error('Thiếu thông tin bắt buộc: bookId, orderId, rating, comment', 400);
            }

            if (rating < 1 || rating > 5 || !Number.isInteger(rating)) {
                throw new Error('Rating phải là số nguyên từ 1 đến 5', 400);
            }

            if (!comment.trim()) {
                throw new Error('Vui lòng nhập nội dung nhận xét', 400);
            }

            if (comment.length > 1000) {
                throw new Error('Nội dung nhận xét không được vượt quá 1000 ký tự', 400);
            }

            // Kiểm tra xem user đã đánh giá sách này trong đơn hàng này chưa
            const existingReview = await Review.findOne({
                userId,
                bookId,
                orderId,
                isHidden: false
            });

            if (existingReview) {
                throw new Error('Bạn đã đánh giá sách này trong đơn hàng này rồi', 400);
            }

            // Kiểm tra xem đơn hàng có tồn tại và thuộc về user không
            try {
                const orderResponse = await axios.get(`${ORDER_SERVICE}/api/order/${orderId}`, {
                    headers: { Authorization: req.headers.authorization }
                });

                const order = orderResponse.data.data.order;

                if (!order) {
                    throw new Error('Đơn hàng không tồn tại', 404);
                }

                if (order.userId.toString() !== userId) {
                    throw new Error('Bạn không có quyền đánh giá sách trong đơn hàng này', 403);
                }

                // Kiểm tra xem đơn hàng đã được giao chưa (cho phép đánh giá khi đã nhận hàng)
                if (order.orderStatus !== 'Delivered') {
                    throw new Error('Chỉ có thể đánh giá sách sau khi đơn hàng đã được giao và bạn đã nhận hàng', 400);
                }

                // Kiểm tra xem sách có trong đơn hàng không
                const bookInOrder = order.items.find(item => item.bookId.toString() === bookId);
                if (!bookInOrder) {
                    throw new Error('Sách này không có trong đơn hàng', 400);
                }

            } catch (error) {
                if (error.response?.status === 404) {
                    throw new Error('Đơn hàng không tồn tại', 404);
                }
                if (error.response?.status === 403) {
                    throw new Error('Bạn không có quyền đánh giá sách trong đơn hàng này', 403);
                }
                throw new Error('Lỗi khi kiểm tra đơn hàng', 500);
            }

            // Kiểm tra xem sách có tồn tại không
            try {
                const bookResponse = await axios.get(`${BOOK_SERVICE}/api/books/${bookId}`);
                if (!bookResponse.data.data.book) {
                    throw new Error('Sách không tồn tại', 404);
                }
            } catch (error) {
                if (error.response?.status === 404) {
                    throw new Error('Sách không tồn tại', 404);
                }
                throw new Error('Lỗi khi kiểm tra thông tin sách', 500);
            }

            // Tạo đánh giá mới - hiển thị ngay lập tức
            const newReview = new Review({
                userId,
                bookId,
                orderId,
                rating,
                comment: comment.trim(),
                status: 'approved', // Hiển thị ngay lập tức
                isVerified: true,   // Đánh dấu là đã xác minh
                approvedAt: new Date(),
                approvedBy: userId  // Tự động phê duyệt
            });

            await newReview.save();

            // Populate thông tin user
            await newReview.populate('user', 'fullName profilePicture');

            return response(res, 201, 'Gửi đánh giá thành công. Đánh giá của bạn đã được hiển thị.', {
                review: newReview
            });

        } catch (error) {
            next(error);
        }
    },

    // Cập nhật đánh giá
    updateReview: async (req, res, next) => {
        try {
            const { id } = req.params;
            const userId = req.user.id;
            const { rating, comment } = req.body;

            // Validation
            if (rating !== undefined && (rating < 1 || rating > 5 || !Number.isInteger(rating))) {
                throw new Error('Rating phải là số nguyên từ 1 đến 5', 400);
            }

            if (comment !== undefined) {
                if (!comment.trim()) {
                    throw new Error('Vui lòng nhập nội dung nhận xét', 400);
                }
                if (comment.length > 1000) {
                    throw new Error('Nội dung nhận xét không được vượt quá 1000 ký tự', 400);
                }
            }

            // Tìm đánh giá
            const review = await Review.findOne({
                _id: id,
                userId,
                isHidden: false // Chỉ cập nhật nếu đánh giá chưa bị ẩn
            });

            if (!review) {
                throw new Error('Đánh giá không tồn tại hoặc bạn không có quyền chỉnh sửa', 404);
            }

            // Cập nhật đánh giá
            const updateData = {};
            if (rating !== undefined) updateData.rating = rating;
            if (comment !== undefined) updateData.comment = comment.trim();

            const updatedReview = await Review.findByIdAndUpdate(
                id,
                updateData,
                { new: true, runValidators: true }
            ).populate('user', 'fullName profilePicture');

            return response(res, 200, 'Cập nhật đánh giá thành công', {
                review: updatedReview
            });

        } catch (error) {
            next(error);
        }
    },

    // Xóa đánh giá (soft delete)
    deleteReview: async (req, res, next) => {
        try {
            const { id } = req.params;
            const userId = req.user.id;

            const review = await Review.findOne({
                _id: id,
                userId,
                isHidden: false // Chỉ xóa nếu đánh giá chưa bị ẩn
            });

            if (!review) {
                throw new Error('Đánh giá không tồn tại hoặc bạn không có quyền xóa', 404);
            }

            // Soft delete
            review.isHidden = true; // Thay thế isDeleted bằng isHidden
            await review.save();

            return response(res, 200, 'Xóa đánh giá thành công');

        } catch (error) {
            next(error);
        }
    },

    // Lấy đánh giá theo ID
    getReviewById: async (req, res, next) => {
        try {
            const { id } = req.params;

            const review = await Review.findOne({
                _id: id,
                isHidden: false  // Chỉ hiển thị đánh giá chưa bị ẩn
            }).populate('user', 'fullName profilePicture');

            if (!review) {
                throw new Error('Đánh giá không tồn tại hoặc đã bị ẩn', 404);
            }

            return response(res, 200, 'Lấy đánh giá thành công', {
                review
            });

        } catch (error) {
            next(error);
        }
    },

    // Lấy đánh giá của user cho một sách
    getUserReviewForBook: async (req, res, next) => {
        try {
            const userId = req.user.id;
            const { bookId, orderId } = req.params;

            const review = await Review.findOne({
                userId,
                bookId,
                orderId,
                isHidden: 'false'
            }).populate('user', 'fullName profilePicture');

            return response(res, 200, 'Lấy đánh giá thành công', {
                review: review || null
            });

        } catch (error) {
            next(error);
        }
    },

    // Lấy tất cả đánh giá của user
    getUserReviews: async (req, res, next) => {
        try {
            const userId = req.user.id;
            const { page = 1, limit = 10 } = req.query;

            const skip = (parseInt(page) - 1) * parseInt(limit);

            const [reviews, total] = await Promise.all([
                Review.find({
                    userId
                })
                    .populate('user', 'fullName profilePicture')
                    .sort({ createdAt: -1 })
                    .skip(skip)
                    .limit(parseInt(limit))
                    .lean(),
                Review.countDocuments({
                    userId,
                    isHidden: false // Chỉ đếm đánh giá chưa bị ẩn
                })
            ]);

            // Populate book information from bookService
            const reviewsWithBooks = await Promise.all(
                reviews.map(async (review) => {
                    try {
                        const bookResponse = await axios.get(`${BOOK_SERVICE}/api/books/${review.bookId}`);
                        return {
                            ...review,
                            book: bookResponse.data.data.book
                        };
                    } catch (error) {
                        return {
                            ...review,
                            book: { title: 'Sách không tồn tại' }
                        };
                    }
                })
            );

            return response(res, 200, 'Lấy danh sách đánh giá thành công', {
                reviews: reviewsWithBooks,
                pagination: {
                    currentPage: parseInt(page),
                    totalPages: Math.ceil(total / parseInt(limit)),
                    totalItems: total,
                    itemsPerPage: parseInt(limit)
                }
            });

        } catch (error) {
            next(error);
        }
    },

    // Lấy đánh giá của một sách (cho admin hoặc public)
    getBookReviews: async (req, res, next) => {
        try {
            const { bookId } = req.params;
            const { page = 1, limit = 10, rating, sort = 'newest' } = req.query;

            if (!mongoose.Types.ObjectId.isValid(bookId)) {
                return response(res, 400, 'bookId không hợp lệ');
            }

            const skip = (parseInt(page) - 1) * parseInt(limit);

            // Build query - chỉ hiển thị đánh giá chưa bị ẩn và đã được phê duyệt
            let query = {
                bookId: new mongoose.Types.ObjectId(bookId),
                isHidden: false // Chỉ hiển thị đánh giá đã được phê duyệt
            };

            if (rating && !isNaN(rating)) {
                query.rating = parseInt(rating);
            }

            // Build sort
            let sortOption = {};
            switch (sort) {
                case 'newest':
                    sortOption = { createdAt: -1 };
                    break;
                case 'oldest':
                    sortOption = { createdAt: 1 };
                    break;
                case 'rating_high':
                    sortOption = { rating: -1, createdAt: -1 };
                    break;
                case 'rating_low':
                    sortOption = { rating: 1, createdAt: -1 };
                    break;
                case 'helpful':
                    sortOption = { helpfulCount: -1, createdAt: -1 };
                    break;
                default:
                    sortOption = { createdAt: -1 };
            }

            const [reviews, total] = await Promise.all([
                Review.find(query)
                    .populate('user', 'fullName profilePicture')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(parseInt(limit))
                    .lean(),
                Review.countDocuments(query)
            ]);

            // Tính toán thống kê rating - chỉ tính những đánh giá hiển thị
            const ratingStats = await Review.aggregate([
                { $match: { bookId: new mongoose.Types.ObjectId(bookId), isHidden: false } },
                {
                    $group: {
                        _id: '$rating',
                        count: { $sum: 1 }
                    }
                },
                { $sort: { _id: -1 } }
            ]);

            const ratingDistribution = {};
            for (let i = 5; i >= 1; i--) {
                const stat = ratingStats.find(s => s._id === i);
                ratingDistribution[i] = stat ? stat.count : 0;
            }

            return response(res, 200, 'Lấy đánh giá sách thành công', {
                reviews,
                ratingDistribution,
                pagination: {
                    currentPage: parseInt(page),
                    totalPages: Math.ceil(total / parseInt(limit)),
                    totalItems: total,
                    itemsPerPage: parseInt(limit)
                }
            });

        } catch (error) {
            console.error(error);
            next(error);
        }
    },

    // Đánh dấu đánh giá là hữu ích
    markReviewHelpful: async (req, res, next) => {
        try {
            const { id } = req.params;
            const userId = req.user.id;

            const review = await Review.findOne({
                _id: id,
                isHidden: false // Chỉ đánh dấu hữu ích nếu đánh giá chưa bị ẩn
            });

            if (!review) {
                throw new Error('Đánh giá không tồn tại', 404);
            }

            // Tăng số lượt hữu ích
            review.helpfulCount += 1;
            await review.save();

            return response(res, 200, 'Đánh dấu hữu ích thành công', {
                helpfulCount: review.helpfulCount
            });

        } catch (error) {
            next(error);
        }
    },

    // Báo cáo đánh giá
    reportReview: async (req, res, next) => {
        try {
            const { id } = req.params;
            const userId = req.user.id;
            const { reason } = req.body;

            if (!reason || !reason.trim()) {
                throw new Error('Vui lòng cung cấp lý do báo cáo', 400);
            }

            const review = await Review.findOne({
                _id: id,
                isHidden: false // Chỉ báo cáo nếu đánh giá chưa bị ẩn
            });

            if (!review) {
                throw new Error('Đánh giá không tồn tại', 404);
            }

            // Tăng số lượt báo cáo
            review.reportCount += 1;
            await review.save();

            // TODO: Lưu chi tiết báo cáo vào collection riêng nếu cần

            return response(res, 200, 'Báo cáo đánh giá thành công');

        } catch (error) {
            next(error);
        }
    },

    // ========== ADMIN APIs ==========

    // Lấy tất cả đánh giá (cho admin)
    getAllReviews: async (req, res, next) => {
        try {
            const { page = 1, limit = 10, sort = 'newest', isHidden } = req.query;

            const skip = (parseInt(page) - 1) * parseInt(limit);

            // Build sort
            let sortOption = {};
            switch (sort) {
                case 'newest':
                    sortOption = { createdAt: -1 };
                    break;
                case 'oldest':
                    sortOption = { createdAt: 1 };
                    break;
                case 'rating_high':
                    sortOption = { rating: -1, createdAt: -1 };
                    break;
                case 'rating_low':
                    sortOption = { rating: 1, createdAt: -1 };
                    break;
                default:
                    sortOption = { createdAt: -1 };
            }

            // Build filter
            let filter = {};
            if (typeof isHidden !== 'undefined') {
                if (isHidden === 'true' || isHidden === true) filter.isHidden = true;
                else if (isHidden === 'false' || isHidden === false) filter.isHidden = false;
            }
            // Nếu không truyền isHidden thì lấy tất cả

            const [reviews, total] = await Promise.all([
                Review.find(filter)
                    .populate('user', 'fullName email profilePicture')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(parseInt(limit))
                    .lean(),
                Review.countDocuments(filter)
            ]);

            // Populate book information from bookService
            const reviewsWithBooks = await Promise.all(
                reviews.map(async (review) => {
                    try {
                        const bookResponse = await axios.get(`${BOOK_SERVICE}/api/books/${review.bookId}`);
                        return {
                            ...review,
                            book: bookResponse.data.data.book
                        };
                    } catch (error) {
                        return {
                            ...review,
                            book: { title: 'Sách không tồn tại' }
                        };
                    }
                })
            );

            return response(res, 200, 'Lấy danh sách đánh giá thành công', {
                reviews: reviewsWithBooks,
                pagination: {
                    currentPage: parseInt(page),
                    totalPages: Math.ceil(total / parseInt(limit)),
                    totalItems: total,
                    itemsPerPage: parseInt(limit)
                }
            });

        } catch (error) {
            next(error);
        }
    },

    // Ẩn đánh giá (admin)
    hideReview: async (req, res, next) => {
        try {
            const { id } = req.params;
            const review = await Review.findById(id);
            if (!review) {
                return response(res, 404, 'Đánh giá không tồn tại');
            }
            review.isHidden = true;
            await review.save();
            return response(res, 200, 'Ẩn đánh giá thành công', { review });
        } catch (error) {
            next(error);
        }
    },

    // Hiện lại đánh giá (admin)
    unhideReview: async (req, res, next) => {
        try {
            const { id } = req.params;
            const review = await Review.findById(id);
            if (!review) {
                return response(res, 404, 'Đánh giá không tồn tại');
            }
            review.isHidden = false;
            await review.save();
            return response(res, 200, 'Hiện lại đánh giá thành công', { review });
        } catch (error) {
            next(error);
        }
    },

    // Lấy danh sách đánh giá đã bị ẩn (admin)
    getHiddenReviews: async (req, res, next) => {
        try {
            const { page = 1, limit = 10, sort = 'newest' } = req.query;

            const skip = (parseInt(page) - 1) * parseInt(limit);

            // Build sort
            let sortOption = {};
            switch (sort) {
                case 'newest':
                    sortOption = { createdAt: -1 };
                    break;
                case 'oldest':
                    sortOption = { createdAt: 1 };
                    break;
                case 'rating_high':
                    sortOption = { rating: -1, createdAt: -1 };
                    break;
                case 'rating_low':
                    sortOption = { rating: 1, createdAt: -1 };
                    break;
                default:
                    sortOption = { createdAt: -1 };
            }

            const [reviews, total] = await Promise.all([
                Review.find({
                    isHidden: true
                })
                    .populate('user', 'fullName email profilePicture')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(parseInt(limit))
                    .lean(),
                Review.countDocuments({
                    isHidden: true
                })
            ]);

            // Populate book information from bookService
            const reviewsWithBooks = await Promise.all(
                reviews.map(async (review) => {
                    try {
                        const bookResponse = await axios.get(`${BOOK_SERVICE}/api/books/${review.bookId}`);
                        return {
                            ...review,
                            book: bookResponse.data.data.book
                        };
                    } catch (error) {
                        return {
                            ...review,
                            book: { title: 'Sách không tồn tại' }
                        };
                    }
                })
            );

            return response(res, 200, 'Lấy danh sách đánh giá đã ẩn thành công', {
                reviews: reviewsWithBooks,
                pagination: {
                    currentPage: parseInt(page),
                    totalPages: Math.ceil(total / parseInt(limit)),
                    totalItems: total,
                    itemsPerPage: parseInt(limit)
                }
            });

        } catch (error) {
            next(error);
        }
    },



    // Lấy trung bình rating cho 1 sách (chỉ tính review hợp lệ)
    getAverageRatingForBook: async (req, res, next) => {
        try {
            const { bookId } = req.params;
            if (!mongoose.Types.ObjectId.isValid(bookId)) {
                return response(res, 400, 'bookId không hợp lệ');
            }
            const match = { bookId: new mongoose.Types.ObjectId(bookId), isHidden: false };
            const stats = await Review.aggregate([
                { $match: match },
                {
                    $group: {
                        _id: null,
                        averageRating: { $avg: '$rating' },
                        totalReviews: { $sum: 1 }
                    }
                }
            ]);
            const averageRating = stats[0]?.averageRating || 0;
            const totalReviews = stats[0]?.totalReviews || 0;
            return response(res, 200, 'Lấy trung bình rating thành công', { averageRating, totalReviews });
        } catch (error) {
            next(error);
        }
    }
};

export default review_controller; 