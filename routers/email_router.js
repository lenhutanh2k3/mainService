import express from 'express';
import email_controller from '../controller/email_controller.js';
import dotenv from 'dotenv';
dotenv.config();
console.log('EMAIL_USER:', process.env.EMAIL_USER);
console.log('EMAIL_PASS:', process.env.EMAIL_PASS ? '***' : 'NOT SET');

const router = express.Router();

// Gửi email thông báo đơn hàng tạo thành công
router.post('/order-confirmation', email_controller.sendOrderConfirmation);

// Gửi email thông báo cập nhật trạng thái đơn hàng
router.post('/order-status', email_controller.sendOrderStatusUpdate);

// Gửi email thông báo thanh toán
router.post('/payment-notification', email_controller.sendPaymentNotification);

export default router; 