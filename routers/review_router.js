import express from 'express';
import review_controller from '../controller/review_controller.js';
import { check_Token, check_admin } from '../middleware/auth_middleware.js';

const router = express.Router();

// ========== ADMIN ROUTES ==========
// Đặt admin routes trước để tránh conflict với user routes

// Lấy tất cả đánh giá (admin)
router.get('/admin/all', check_Token, check_admin, review_controller.getAllReviews);

// Lấy danh sách đánh giá đã ẩn (admin)
router.get('/admin/hidden', check_Token, check_admin, review_controller.getHiddenReviews);

// Thống kê đánh giá (admin)
router.get('/admin/stats', check_Token, check_admin, review_controller.getReviewStats);

// Ẩn đánh giá (admin)
router.put('/admin/:id/hide', check_Token, check_admin, review_controller.hideReview);

// Hiển thị lại đánh giá đã ẩn (admin)
router.put('/admin/:id/unhide', check_Token, check_admin, review_controller.unhideReview);

// ========== USER ROUTES ==========

// Tạo đánh giá mới (yêu cầu đăng nhập)
router.post('/', check_Token, review_controller.createReview);

// Cập nhật đánh giá (yêu cầu đăng nhập và là chủ sở hữu)
router.put('/:id', check_Token, review_controller.updateReview);

// Xóa đánh giá (yêu cầu đăng nhập và là chủ sở hữu)
router.delete('/:id', check_Token, review_controller.deleteReview);

// Lấy đánh giá theo ID (public)
router.get('/:id', review_controller.getReviewById);

// Lấy đánh giá của user cho một sách cụ thể (yêu cầu đăng nhập)
router.get('/user/:bookId/:orderId', check_Token, review_controller.getUserReviewForBook);

// Lấy tất cả đánh giá của user (yêu cầu đăng nhập)
router.get('/user/all', check_Token, review_controller.getUserReviews);

// Lấy đánh giá của một sách (public)
router.get('/book/:bookId', review_controller.getBookReviews);

// Đánh dấu đánh giá là hữu ích (yêu cầu đăng nhập)
router.post('/:id/helpful', check_Token, review_controller.markReviewHelpful);

export default router; 